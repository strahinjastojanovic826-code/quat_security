use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::QuadError;
use crate::state::{QuadReason, QuadState, StateEvent};
use crate::state::QuadAction;
use crate::metrics::SystemMetrics;
use crate::hysteresis::HysteresisEvaluator;

#[cfg(target_os = "linux")]
use std::fs;

pub type StateChangeCallback = unsafe extern "C" fn(QuadState, QuadState, QuadReason);

pub struct QuadGuardInner {
    pub current_state: QuadState,
    pub ram_threshold: u32,
    pub cpu_threshold: u32,
    pub action_policy: QuadAction,
    pub history: [StateEvent; 10],
    pub history_count: usize,
    pub last_error: QuadError,
    pub callback: Option<StateChangeCallback>,
}

#[derive(Clone)]
pub struct QuadGuard {
    pub inner: Arc<Mutex<QuadGuardInner>>,
}

impl QuadGuard {
    pub fn new() -> Self {
        let inner = QuadGuardInner {
            current_state: QuadState::Nominal,
            ram_threshold: 80,
            cpu_threshold: 80,
            action_policy: QuadAction::TerminateProcess,
            history: [StateEvent::new(
                QuadState::Nominal,
                QuadState::Nominal,
                QuadReason::None,
                0,
            ); 10],
            history_count: 0,
            last_error: QuadError::Ok,
            callback: None,
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub fn set_threshold(&self, new_threshold: u32) -> QuadError {
        if let Ok(mut guard) = self.inner.lock() {
            if new_threshold <= 100 {
                guard.ram_threshold = new_threshold;
            }
            QuadError::Ok
        } else {
            QuadError::LockError
        }
    }

    pub fn analyze_multivariate(&self, metrics: SystemMetrics) -> QuadState {
    if let Ok(mut inner) = self.inner.lock() {
        let evaluator = HysteresisEvaluator::default();
        let threat_score = metrics.calculate_threat_score();
        
        let current_state = inner.current_state;
        let next_state = evaluator.evaluate_next_state(current_state, threat_score);

        if current_state != next_state {
            let reason = match next_state {
                QuadState::Elevated => QuadReason::MemoryThresholdExceeded,
                QuadState::Critical => QuadReason::MemoryThresholdExceeded,
                QuadState::Lockdown => QuadReason::ProcessTerminationFailure,
                QuadState::Nominal => QuadReason::None,
            };

            QuadGuard::record_transition_with_reason(&mut inner, next_state, reason);
        }

        inner.current_state
    } else {
        QuadState::Nominal
    }
}

    pub fn set_callback(&self, cb: Option<StateChangeCallback>) -> QuadError {
        if let Ok(mut guard) = self.inner.lock() {
            guard.callback = cb;
            QuadError::Ok
        } else {
            QuadError::LockError
        }
    }

    pub fn record_transition_with_reason(
        inner: &mut QuadGuardInner,
        next_state: QuadState,
        reason: QuadReason,
    ) {
        if inner.current_state != next_state {
            let previous = inner.current_state;
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let event = StateEvent::new(previous, next_state, reason, timestamp);

            if inner.history_count < 10 {
                inner.history[inner.history_count] = event;
                inner.history_count += 1;
            } else {
                inner.history.rotate_left(1);
                inner.history[9] = event;
            }

            inner.current_state = next_state;

            if let Some(cb) = inner.callback {
                unsafe {
                    cb(previous, next_state, reason);
                }
            }
            let state_str = match next_state {
    QuadState::Nominal => "Nominal",
    QuadState::Elevated => "Elevated",
    QuadState::Critical => "Critical",
    QuadState::Lockdown => "Lockdown",
};
crate::actions::ActionExecutor::trigger_external_action(state_str, inner.ram_threshold, None);
        }
    }

    pub fn analyze(&self) -> QuadState {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return QuadState::Nominal,
        };

        #[cfg(target_os = "windows")]
        {
            use crate::native_api::win_api::*;
            let mut status = MEMORYSTATUSEX {
                dw_length: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
                dw_memory_load: 0,
                ull_total_phys: 0,
                ull_avail_phys: 0,
                ull_total_page_file: 0,
                ull_avail_page_file: 0,
                ull_total_virtual: 0,
                ull_avail_virtual: 0,
                ull_avail_extended_virtual: 0,
            };

            unsafe {
                if GlobalMemoryStatusEx(&mut status) != 0 {
                    let target_state = if status.dw_memory_load > guard.ram_threshold {
                        QuadState::Elevated
                    } else {
                        QuadState::Nominal
                    };

                    let reason = if target_state == QuadState::Elevated {
                        QuadReason::MemoryThresholdExceeded
                    } else {
                        QuadReason::None
                    };

                    Self::record_transition_with_reason(&mut guard, target_state, reason);
                }
            }
        }

        #[cfg(target_os = "macos")]
{
    if let Ok((total_mem, free_mem)) = crate::native_api::macos_api::get_mac_memory_usage() {
        if total_mem > 0 {
            let used_mem = total_mem.saturating_sub(free_mem);
            let load_pct = ((used_mem * 100) / total_mem) as u32;
            
            let target_state = if load_pct > guard.ram_threshold {
                QuadState::Elevated
            } else {
                QuadState::Nominal
            };
            
            let reason = if target_state == QuadState::Elevated {
                QuadReason::MemoryThresholdExceeded
            } else {
                QuadReason::None
            };
            
            Self::record_transition_with_reason(&mut guard, target_state, reason);
        }
    }
}

        #[cfg(target_os = "linux")]
        {
            if let Ok(mem_info) = fs::read_to_string("/proc/meminfo") {
                let mut total_mem: u64 = 0;
                let mut free_mem: u64 = 0;

                for line in mem_info.lines() {
                    if line.starts_with("MemTotal:") {
                        total_mem = line
                            .split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                    } else if line.starts_with("MemAvailable:") {
                        free_mem = line
                            .split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                    }
                }

                if total_mem > 0 {
                    let used_mem = total_mem.saturating_sub(free_mem);
                    let load_pct = ((used_mem * 100) / total_mem) as u32;

                    let target_state = if load_pct > guard.ram_threshold {
                        QuadState::Elevated
                    } else {
                        QuadState::Nominal
                    };

                    let reason = if target_state == QuadState::Elevated {
                        QuadReason::MemoryThresholdExceeded
                    } else {
                        QuadReason::None
                    };

                    Self::record_transition_with_reason(&mut guard, target_state, reason);
                }
            }
        }

        guard.current_state
    }
}

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

pub struct SecurityWatchdog {
    last_heartbeat: Arc<AtomicU64>,
    is_running: Arc<AtomicBool>,
}

impl SecurityWatchdog {
    pub fn new(timeout: Duration) -> Self {
        let last_heartbeat = Arc::new(AtomicU64::new(Self::now_ms()));
        let is_running = Arc::new(AtomicBool::new(true));

        let hb_clone = Arc::clone(&last_heartbeat);
        let run_clone = Arc::clone(&is_running);

        // Spawn independent background monitor thread
        thread::spawn(move || {
            while run_clone.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(200));
                let current_time = Self::now_ms();
                let last = hb_clone.load(Ordering::Acquire);

                if current_time - last > timeout.as_millis() as u64 {
                    eprintln!("[FAIL-SAFE CRITICAL] Watchdog timeout reached! Forcing system LOCKDOWN (11)...");
                    // TRIGGER FAIL-SAFE: Execute emergency lockdown/process termination here
                    break;
                }
            }
        });

        Self {
            last_heartbeat,
            is_running,
        }
    }

    /// Call this method periodically in your main guard loop to prove healthiness
    pub fn kick(&self) {
        self.last_heartbeat.store(Self::now_ms(), Ordering::Release);
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

impl Drop for SecurityWatchdog {
    fn drop(&mut self) {
        self.is_running.store(false, Ordering::Release);
    }
}