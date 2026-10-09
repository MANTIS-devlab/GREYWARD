//! Bounded fixed-provider execution, not the privileged native isolation runner.
//! Descendants may not keep an output reader alive beyond the request deadline.
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::process::{Pid, PidfdFlags, Signal, kill_process_group, pidfd_open};
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{
    Arc, Condvar, Mutex, OnceLock,
    atomic::{AtomicUsize, Ordering},
    mpsc::{self, SyncSender},
};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(8);
const OUTPUT_LIMIT: usize = 1024 * 1024;
const MAX_PROVIDER_CHILDREN: usize = 32;
const MAX_PROVIDER_WORKERS: usize = 4;
const MAX_PROVIDER_JOBS: usize = 8;
type ProviderJob = Box<dyn FnOnce() + Send + 'static>;

// spawn() can block on executable/loader I/O before a Child exists. Keep it
// off the requesting thread, with a fixed worker/admission bound. A timed-out
// caller does not claim cancellation: a stalled worker retains its slot until
// it returns, establishes child ownership and performs deadline cleanup.
struct ProviderWorkers {
    jobs: SyncSender<ProviderJob>,
    capacity: Arc<AtomicUsize>,
    maximum: usize,
}

impl ProviderWorkers {
    fn new(worker_count: usize, maximum: usize) -> io::Result<Self> {
        let (jobs, receiver) = mpsc::sync_channel::<ProviderJob>(maximum);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..worker_count {
            let receiver = Arc::clone(&receiver);
            std::thread::Builder::new()
                .name(format!("provider-worker-{index}"))
                .spawn(move || {
                    loop {
                        let next = receiver
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv();
                        let Ok(job) = next else { break };
                        job();
                    }
                })?;
        }
        Ok(Self {
            jobs,
            capacity: Arc::new(AtomicUsize::new(0)),
            maximum,
        })
    }

    fn call<T: Send + 'static>(
        &self,
        deadline: Instant,
        work: impl FnOnce() -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Provider deadline expired",
            ));
        }
        let slot = ProviderSlot::acquire_maximum(&self.capacity, self.maximum)?;
        let (sender, receiver) = mpsc::sync_channel(1);
        self.jobs
            .try_send(Box::new(move || {
                let _slot = slot;
                // Expired queued work never starts a provider. The admission slot
                // survives caller timeout; it is not released by dropping receiver.
                let result = if Instant::now() < deadline {
                    work()
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Provider deadline expired",
                    ))
                };
                let _ = sender.send(result);
            }))
            .map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "Provider worker unavailable")
            })?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Provider deadline expired"))?;
        let result = receiver
            .recv_timeout(remaining)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => {
                    io::Error::new(io::ErrorKind::TimedOut, "Provider deadline expired")
                }
                mpsc::RecvTimeoutError::Disconnected => io::Error::other("Provider worker failed"),
            })?;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Provider deadline expired",
            ));
        }
        result
    }
}

fn workers() -> io::Result<&'static ProviderWorkers> {
    static WORKERS: OnceLock<Option<ProviderWorkers>> = OnceLock::new();
    WORKERS
        .get_or_init(|| ProviderWorkers::new(MAX_PROVIDER_WORKERS, MAX_PROVIDER_JOBS).ok())
        .as_ref()
        .ok_or_else(|| io::Error::other("Provider workers unavailable"))
}

// A kernel-stalled killed process must not turn a response deadline into a
// blocking wait. Retain its unreaped leader and admission slot until the one
// background reaper observes exit. No per-request cleanup thread or detached
// unbounded work is created. Saturation is an explicit provider failure.
struct ProviderSlot(Arc<AtomicUsize>);

impl ProviderSlot {
    fn acquire(counter: &Arc<AtomicUsize>) -> io::Result<Self> {
        Self::acquire_maximum(counter, MAX_PROVIDER_CHILDREN)
    }

    fn acquire_maximum(counter: &Arc<AtomicUsize>, maximum: usize) -> io::Result<Self> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < maximum).then_some(current + 1)
            })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "Provider child capacity reached")
            })?;
        Ok(Self(Arc::clone(counter)))
    }
}
impl Drop for ProviderSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct PendingChild {
    child: Child,
    _slot: ProviderSlot,
}
struct Reaper {
    pending: Mutex<Vec<PendingChild>>,
    changed: Condvar,
    capacity: Arc<AtomicUsize>,
}

fn reaper() -> io::Result<&'static Arc<Reaper>> {
    static REAPER: OnceLock<Option<Arc<Reaper>>> = OnceLock::new();
    REAPER
        .get_or_init(|| {
            let state = Arc::new(Reaper {
                pending: Mutex::new(Vec::with_capacity(MAX_PROVIDER_CHILDREN)),
                changed: Condvar::new(),
                capacity: Arc::new(AtomicUsize::new(0)),
            });
            let worker = Arc::clone(&state);
            std::thread::Builder::new()
                .name("provider-reaper".into())
                .spawn(move || {
                    let mut pending = worker
                        .pending
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    loop {
                        // try_wait is waitpid(WNOHANG), not filesystem/provider I/O.
                        // Keep an unobservable child and its slot instead of forgetting
                        // cleanup or allowing capacity to grow beyond the fixed bound.
                        let mut index = 0;
                        while index < pending.len() {
                            if matches!(pending[index].child.try_wait(), Ok(Some(_))) {
                                pending.swap_remove(index);
                            } else {
                                index += 1;
                            }
                        }
                        pending = if pending.is_empty() {
                            worker
                                .changed
                                .wait(pending)
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                        } else {
                            worker
                                .changed
                                .wait_timeout(pending, Duration::from_millis(50))
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .0
                        };
                    }
                })
                .ok()?;
            Some(state)
        })
        .as_ref()
        .ok_or_else(|| io::Error::other("Provider cleanup worker unavailable"))
}

struct ProviderChild {
    child: Option<Child>,
    group: Option<Pid>,
    slot: Option<ProviderSlot>,
    reaper: &'static Arc<Reaper>,
}

impl Drop for ProviderChild {
    fn drop(&mut self) {
        // Do this before wait/reaping: the direct child anchors the group ID.
        // This is cleanup of a fixed provider, not containment of hostile code
        // that deliberately leaves its process group. Root launch workers use
        // root-controlled workload membership instead.
        if let Some(group) = self.group.take() {
            let _ = kill_process_group(group, Signal::KILL);
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                if !matches!(child.try_wait(), Ok(Some(_))) {
                    // The admission slot accounts for running AND retained
                    // children, so this queue cannot grow beyond 32 entries.
                    let pending = PendingChild {
                        child,
                        _slot: self.slot.take().expect("Every provider owns one slot"),
                    };
                    self.reaper
                        .pending
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(pending);
                    self.reaper.changed.notify_one();
                }
            }
        }
    }
}

fn nonblocking(pipe: &impl AsFd) -> io::Result<()> {
    let flags = fcntl_getfl(pipe)?;
    Ok(fcntl_setfl(pipe, flags | OFlags::NONBLOCK)?)
}

fn drain(
    pipe: &mut impl Read,
    bytes: &mut Vec<u8>,
    limit: usize,
    deadline: Instant,
) -> io::Result<bool> {
    // Bound work per pipe so stderr and the deadline cannot be starved by stdout.
    for _ in 0..4 {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Provider deadline expired",
            ));
        }
        let mut buffer = [0_u8; 16 * 1024];
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if count > limit.saturating_sub(bytes.len()) {
                    return Err(io::Error::new(
                        io::ErrorKind::FileTooLarge,
                        "Provider output limit exceeded",
                    ));
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

pub(crate) fn bounded_output(program: &str, arguments: &[&str]) -> io::Result<Output> {
    run(program, arguments, TIMEOUT, OUTPUT_LIMIT)
}

pub(crate) fn bounded_output_until(
    program: &str,
    arguments: &[&str],
    deadline: Instant,
) -> io::Result<Output> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Provider deadline expired"))?;
    run(program, arguments, remaining.min(TIMEOUT), OUTPUT_LIMIT)
}

fn run(program: &str, arguments: &[&str], timeout: Duration, limit: usize) -> io::Result<Output> {
    run_with_environment(program, arguments, timeout, limit, false)
}

pub(crate) fn rpm_metadata_output(path: &str, deadline: Instant) -> io::Result<Output> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Provider deadline expired"))?;
    run_with_environment(
        "/usr/bin/rpm",
        &[
            "--query",
            "--file",
            path,
            "--queryformat",
            crate::rpm_metadata::RPM_EXECUTABLE_QUERY,
        ],
        remaining.min(TIMEOUT),
        OUTPUT_LIMIT,
        true,
    )
}

fn run_with_environment(
    program: &str,
    arguments: &[&str],
    timeout: Duration,
    limit: usize,
    clean: bool,
) -> io::Result<Output> {
    let deadline = Instant::now() + timeout;
    if program.len() > 4096
        || arguments.len() > 64
        || arguments
            .iter()
            .try_fold(0_usize, |total, value| total.checked_add(value.len()))
            .is_none_or(|total| total > 128 * 1024)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Provider input limit exceeded",
        ));
    }
    let program = program.to_owned();
    let arguments: Vec<String> = arguments.iter().map(|value| (*value).to_owned()).collect();
    workers()?.call(deadline, move || {
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        run_worker(&program, &arguments, deadline, limit, clean)
    })
}

fn run_worker(
    program: &str,
    arguments: &[&str],
    deadline: Instant,
    limit: usize,
    clean: bool,
) -> io::Result<Output> {
    let reaper = reaper()?;
    let slot = ProviderSlot::acquire(&reaper.capacity)?;
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Provider deadline expired",
        ));
    }
    let mut command = Command::new(program);
    if clean {
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .env("LANG", "C")
            .env("LC_ALL", "C");
    }
    let child = command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()?;
    let group = Pid::from_raw(i32::try_from(child.id()).map_err(io::Error::other)?)
        .ok_or_else(|| io::Error::other("Provider process identity is unavailable"))?;
    let mut child = ProviderChild {
        child: Some(child),
        group: Some(group),
        slot: Some(slot),
        reaper,
    };
    let pidfd = pidfd_open(group, PidfdFlags::empty())?;
    let mut stdout = child
        .child
        .as_mut()
        .expect("Provider is held until cleanup")
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Missing stdout"))?;
    let mut stderr = child
        .child
        .as_mut()
        .expect("Provider is held until cleanup")
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("Missing stderr"))?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Provider deadline expired",
            ));
        }
        if !stdout_eof {
            stdout_eof = drain(&mut stdout, &mut stdout_bytes, limit, deadline)?;
        }
        if !stderr_eof {
            stderr_eof = drain(&mut stderr, &mut stderr_bytes, limit, deadline)?;
        }
        // Do not reap the leader while descendants can retain a pipe. Once
        // both pipes close, poll the held pidfd without reaping. Kill remaining
        // group members while the exited leader still anchors its numeric ID.
        if stdout_eof && stderr_eof {
            let mut descriptors = [PollFd::new(&pidfd, PollFlags::IN)];
            if poll(
                &mut descriptors,
                Some(&Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            )? != 0
            {
                let _ = kill_process_group(group, Signal::KILL);
                let status = child
                    .child
                    .as_mut()
                    .expect("Provider is held until cleanup")
                    .wait()?;
                child.group = None;
                return Ok(Output {
                    status,
                    stdout: stdout_bytes,
                    stderr: stderr_bytes,
                });
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_deadline_does_not_release_stalled_work_or_start_expired_queue() {
        let pool = ProviderWorkers::new(1, 2).unwrap();
        let (started, observed) = mpsc::sync_channel(1);
        let (release, held) = mpsc::sync_channel(1);
        let began = Instant::now();
        let error = pool
            .call(began + Duration::from_millis(100), move || {
                started.send(()).unwrap();
                held.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(began.elapsed() < Duration::from_secs(2));
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(pool.capacity.load(Ordering::Acquire), 1);

        // A queued provider expires while the first worker is stalled. It must
        // not start later, and dropping either caller must not free admission.
        let executed = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&executed);
        assert_eq!(
            pool.call(Instant::now() + Duration::from_millis(50), move || {
                count.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(pool.capacity.load(Ordering::Acquire), 2);
        assert_eq!(
            pool.call(Instant::now() + Duration::from_secs(1), || Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );

        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while pool.capacity.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(pool.capacity.load(Ordering::Acquire), 0);
        assert_eq!(executed.load(Ordering::Acquire), 0);
        assert_eq!(
            pool.call(Instant::now() + Duration::from_secs(1), || Ok(7))
                .unwrap(),
            7
        );
    }

    #[test]
    fn expired_work_is_refused_before_dispatch() {
        let pool = ProviderWorkers::new(1, 1).unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        assert_eq!(
            pool.call(Instant::now(), move || {
                sender.send(()).unwrap();
                Ok(())
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(receiver.try_recv().is_err());
        assert_eq!(pool.capacity.load(Ordering::Acquire), 0);
    }

    #[test]
    fn retained_cleanup_slots_bound_admission_and_release_after_reaping() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut held: Vec<_> = (0..MAX_PROVIDER_CHILDREN)
            .map(|_| ProviderSlot::acquire(&counter).unwrap())
            .collect();
        assert_eq!(
            ProviderSlot::acquire(&counter).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(counter.load(Ordering::Acquire), MAX_PROVIDER_CHILDREN);
        held.pop();
        let replacement = ProviderSlot::acquire(&counter).unwrap();
        assert!(ProviderSlot::acquire(&counter).is_err());
        drop(held);
        drop(replacement);
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[test]
    fn failed_provider_cleanup_reaps_a_real_child_and_releases_its_slot() {
        let counter = Arc::new(AtomicUsize::new(0));
        let slot = ProviderSlot::acquire(&counter).unwrap();
        let child = Command::new("/usr/bin/python3")
            .args(["-I", "-c", "import time; time.sleep(30)"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let group = Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
        let pidfd = pidfd_open(group, PidfdFlags::empty()).unwrap();
        let owned = ProviderChild {
            child: Some(child),
            group: Some(group),
            slot: Some(slot),
            reaper: reaper().unwrap(),
        };
        let started = Instant::now();
        drop(owned);
        assert!(started.elapsed() < Duration::from_secs(1));
        let deadline = Instant::now() + Duration::from_secs(2);
        while counter.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(counter.load(Ordering::Acquire), 0);
        let mut descriptors = [PollFd::new(&pidfd, PollFlags::IN)];
        assert_eq!(
            poll(
                &mut descriptors,
                Some(&Timespec {
                    tv_sec: 0,
                    tv_nsec: 0
                })
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn drains_both_pipes_and_preserves_failure_status() {
        let output = run(
            "/usr/bin/python3",
            &[
                "-c",
                "import os; os.write(1,b'x'*100000); os.write(2,b'y'*100000); raise SystemExit(7)",
            ],
            Duration::from_secs(2),
            200_000,
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, vec![b'x'; 100_000]);
        assert_eq!(output.stderr, vec![b'y'; 100_000]);
    }

    #[test]
    fn inherited_pipes_do_not_defeat_the_deadline() {
        let started = Instant::now();
        let error = run(
            "/usr/bin/python3",
            &[
                "-c",
                "import os,time; child=os.fork(); time.sleep(30) if child==0 else os._exit(0)",
            ],
            Duration::from_millis(100),
            4096,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn unbounded_output_fails_without_returning_truncated_success() {
        let error = run(
            "/usr/bin/python3",
            &["-c", "import os;\nwhile True: os.write(1,b'x'*8192)"],
            Duration::from_secs(2),
            4096,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
    }

    #[test]
    fn provider_stdin_is_closed() {
        let output = run(
            "/usr/bin/python3",
            &["-c", "import sys; print(len(sys.stdin.buffer.read()))"],
            Duration::from_secs(2),
            4096,
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"0\n");
    }

    #[test]
    fn an_expired_shared_deadline_never_starts_another_provider() {
        let failure =
            bounded_output_until("/nonexistent/provider", &[], Instant::now()).unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn clean_metadata_provider_does_not_inherit_configuration() {
        let output = run_with_environment(
            "/usr/bin/python3",
            &[
                "-I",
                "-c",
                "import os,json; print(json.dumps(dict(os.environ),sort_keys=True))",
            ],
            Duration::from_secs(2),
            4096,
            true,
        )
        .unwrap();
        assert!(output.status.success());
        let environment: std::collections::BTreeMap<String, String> =
            serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            environment,
            std::collections::BTreeMap::from([
                ("HOME".into(), "/nonexistent".into()),
                ("LANG".into(), "C".into()),
                ("LC_ALL".into(), "C".into()),
                ("PATH".into(), "/usr/bin:/bin".into())
            ])
        );
    }
}
