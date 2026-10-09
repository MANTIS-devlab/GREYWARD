//! Fixed read worker owns process/filesystem/SQLite verification. A syscall
//! stall cannot prolong the transport's wait or release the outstanding slot.
//! No mutation, cancellation or kernel-stall termination is implied.
use crate::{BrokerError, ReadRequest};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc::{self, SyncSender},
};
use std::time::Instant;

const MAX_READ_JOBS: usize = 8;

struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Job {
    // Release this job's admission before a panic disconnects its response.
    // Callers observing worker failure must not race its unfinished slot drop.
    _slot: Slot,
    sender: String,
    request: ReadRequest,
    deadline: Instant,
    result: SyncSender<Result<String, BrokerError>>,
}

pub(crate) struct ReadWorker {
    jobs: SyncSender<Job>,
    capacity: Arc<AtomicUsize>,
}

impl ReadWorker {
    pub(crate) fn new(
        mut handler: impl FnMut(&str, ReadRequest, Instant) -> Result<String, BrokerError>
        + Send
        + 'static,
    ) -> Result<Self, BrokerError> {
        let (jobs, receiver) = mpsc::sync_channel::<Job>(MAX_READ_JOBS);
        std::thread::Builder::new()
            .name("application-read-worker".into())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    // The slot remains owned here after its caller times out.
                    // Expired queued work performs no process/database access.
                    let result = if Instant::now() < job.deadline {
                        handler(&job.sender, job.request, job.deadline)
                    } else {
                        Err(BrokerError::Deadline)
                    };
                    let result = if Instant::now() < job.deadline {
                        result
                    } else {
                        Err(BrokerError::Deadline)
                    };
                    let _ = job.result.send(result);
                }
            })
            .map_err(|_| BrokerError::Transport)?;
        Ok(Self {
            jobs,
            capacity: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub(crate) fn call(
        &self,
        sender: &str,
        request: ReadRequest,
        deadline: Instant,
    ) -> Result<String, BrokerError> {
        if Instant::now() >= deadline {
            return Err(BrokerError::Deadline);
        }
        self.capacity
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_READ_JOBS).then_some(current + 1)
            })
            .map_err(|_| BrokerError::Capacity)?;
        let slot = Slot(Arc::clone(&self.capacity));
        let (result, receiver) = mpsc::sync_channel(1);
        self.jobs
            .try_send(Job {
                sender: sender.to_owned(),
                request,
                deadline,
                result,
                _slot: slot,
            })
            .map_err(|_| BrokerError::Transport)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(BrokerError::Deadline)?;
        let result = receiver
            .recv_timeout(remaining)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => BrokerError::Deadline,
                mpsc::RecvTimeoutError::Disconnected => BrokerError::Transport,
            })?;
        if Instant::now() >= deadline {
            return Err(BrokerError::Deadline);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    #[test]
    fn stalled_verification_retains_capacity_and_expired_jobs_do_not_run() {
        let (release, blocked) = mpsc::sync_channel::<()>(1);
        let (started, seen) = mpsc::sync_channel::<String>(MAX_READ_JOBS);
        let worker = ReadWorker::new(move |sender, _, _| {
            started.send(sender.to_owned()).unwrap();
            if sender == ":1.1" {
                blocked.recv().unwrap();
            }
            Ok(sender.to_owned())
        })
        .unwrap();
        assert!(matches!(
            worker.call(
                ":1.1",
                ReadRequest::Coverage,
                Instant::now() + Duration::from_millis(30)
            ),
            Err(BrokerError::Deadline)
        ));
        assert_eq!(seen.recv_timeout(Duration::from_secs(1)).unwrap(), ":1.1");
        assert_eq!(worker.capacity.load(Ordering::Acquire), 1);
        for index in 2..=MAX_READ_JOBS {
            assert!(matches!(
                worker.call(
                    &format!(":1.{index}"),
                    ReadRequest::Coverage,
                    Instant::now() + Duration::from_millis(5)
                ),
                Err(BrokerError::Deadline)
            ));
        }
        assert_eq!(worker.capacity.load(Ordering::Acquire), MAX_READ_JOBS);
        assert!(matches!(
            worker.call(
                ":1.99",
                ReadRequest::Coverage,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(BrokerError::Capacity)
        ));
        release.send(()).unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while worker.capacity.load(Ordering::Acquire) != 0 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(worker.capacity.load(Ordering::Acquire), 0);
        assert!(seen.try_recv().is_err());
        assert_eq!(
            worker
                .call(
                    ":1.100",
                    ReadRequest::Coverage,
                    Instant::now() + Duration::from_secs(1)
                )
                .unwrap(),
            ":1.100"
        );
        assert_eq!(seen.recv_timeout(Duration::from_secs(1)).unwrap(), ":1.100");
    }

    #[test]
    fn expired_calls_and_failed_workers_never_produce_success() {
        let count = Arc::new(Mutex::new(0));
        let observed = Arc::clone(&count);
        let worker = ReadWorker::new(move |_, _, _| {
            *observed.lock().unwrap() += 1;
            panic!("Synthetic read worker failure")
        })
        .unwrap();
        assert!(matches!(
            worker.call(":1.1", ReadRequest::Coverage, Instant::now()),
            Err(BrokerError::Deadline)
        ));
        assert_eq!(*count.lock().unwrap(), 0);
        assert!(matches!(
            worker.call(
                ":1.2",
                ReadRequest::Coverage,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(BrokerError::Transport)
        ));
        assert_eq!(*count.lock().unwrap(), 1);
        assert_eq!(worker.capacity.load(Ordering::Acquire), 0);
        assert!(matches!(
            worker.call(
                ":1.3",
                ReadRequest::Coverage,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(BrokerError::Transport)
        ));
        assert_eq!(worker.capacity.load(Ordering::Acquire), 0);
    }
}
