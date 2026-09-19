#![allow(clippy::missing_errors_doc)]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

pub struct CollectionGeneration(Arc<AtomicBool>);
impl CollectionGeneration {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    pub fn cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}
impl Default for CollectionGeneration {
    fn default() -> Self {
        Self::new()
    }
}
pub trait Collector: Send + 'static {
    type Output: Send + 'static;
    fn id(&self) -> &'static str;
    fn collect(self, generation: Arc<CollectionGeneration>) -> Result<Self::Output, String>;
}
pub fn collect_concurrently<C: Collector>(
    collectors: Vec<C>,
    timeout: Duration,
) -> Vec<(String, Result<C::Output, String>)> {
    let generation = Arc::new(CollectionGeneration::new());
    let mut handles = Vec::new();
    for c in collectors {
        let id = c.id().to_owned();
        let g = Arc::clone(&generation);
        handles.push((id, thread::spawn(move || c.collect(g))));
    }
    let start = Instant::now();
    let mut out = Vec::new();
    for (id, h) in handles {
        if start.elapsed() > timeout {
            generation.cancel();
            out.push((id, Err("collection-timeout".into())));
        } else {
            out.push((
                id,
                h.join()
                    .unwrap_or_else(|_| Err("collector-panicked".into())),
            ));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}
