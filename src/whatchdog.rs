use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub type WatchdogTimeoutCallback = Box<dyn Fn() + Send + Sync + 'static>;

pub struct SecurityWatchdog {
    last_heartbeat_ms: Arc<AtomicU64>,
    is_running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl SecurityWatchdog {
    pub fn start<F>(timeout: Duration, poll_interval: Duration, on_timeout: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        let now = Self::now_ms();
        let last_heartbeat_ms = Arc::new(AtomicU64::new(now));
        let is_running = Arc::new(AtomicBool::new(true));

        let hb_thread = Arc::clone(&last_heartbeat_ms);
        let running_thread = Arc::clone(&is_running);
        let timeout_ms = timeout.as_millis() as u64;
        let on_timeout: WatchdogTimeoutCallback = Box::new(on_timeout);

        let worker = thread::spawn(move || {
            while running_thread.load(Ordering::Acquire) {
                thread::sleep(poll_interval);
                if !running_thread.load(Ordering::Acquire) {
                    break;
                }

                let current = Self::now_ms();
                let last = hb_thread.load(Ordering::Acquire);
                let elapsed = current.saturating_sub(last);

                if elapsed > timeout_ms {
                    on_timeout();
                    running_thread.store(false, Ordering::Release);
                    break;
                }
            }
        });

        Self {
            last_heartbeat_ms,
            is_running,
            worker: Some(worker),
        }
    }

    pub fn kick(&self) {
        self.last_heartbeat_ms
            .store(Self::now_ms(), Ordering::Release);
    }

    pub fn is_alive(&self) -> bool {
        self.is_running.load(Ordering::Acquire)
    }

    pub fn stop(&mut self) {
        self.is_running.store(false, Ordering::Release);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

impl Drop for SecurityWatchdog {
    fn drop(&mut self) {
        self.stop();
    }
}