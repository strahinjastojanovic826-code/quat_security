use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::QuadError;
use crate::state::{QuadReason, QuadState, StateEvent};

#[cfg(target_os = "linux")]
use std::fs;

pub type StateChangeCallback = unsafe extern "C" fn(QuadState, QuadState, QuadReason);

pub struct QuadGuardInner {
    pub current_state: QuadState,
    pub ram_threshold: u32,
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