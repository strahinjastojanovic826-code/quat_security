//! C-ABI Foreign Function Interface (`extern "C"`) for `QuadGuard`.
//!
//! # Safety Contract (Applies to `unsafe extern "C"` entry points in this module)
//! - Any non-null `ptr` / `out_snap` passed across FFI must point to a valid, properly aligned,
//!   live `QuadGuard` or `QuadCabiSnapshot` instance created by this library or the caller,
//!   and must not be concurrently mutated/freed in violation of Rust aliasing rules.
//! - Functions returning owned raw pointers (`quad_guard_new`, `quad_guard_clone_ref`,
//!   `quad_guard_clone_handle`) transfer ownership to the caller, who must eventually release
//!   them via the corresponding free/consume function (`quad_guard_free` /
//!   `quad_guard_consume_and_destroy`) without double-freeing.
//! - Functions consuming a pointer (`quad_guard_free`, `quad_guard_consume_and_destroy`)
//!   invalidate the handle after freeing; callers must not use the pointer afterward.
//! - Panics are caught via `catch_unwind` so unwinding never crosses the FFI boundary.

use std::panic::{catch_unwind, AssertUnwindSafe};
use crate::errors::QuadError;
use crate::guard::{QuadGuard, StateChangeCallback};
use crate::state::QuadState;
use std::ptr;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_new() -> *mut QuadGuard {
    let result = catch_unwind(|| {
        Box::into_raw(Box::new(QuadGuard::new()))
    });
    result.unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_free(ptr: *mut QuadGuard) { unsafe {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(ptr));
    }));
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_set_callback(
    ptr: *mut QuadGuard,
    cb: Option<StateChangeCallback>,
) -> QuadError { unsafe {
    if ptr.is_null() {
        return QuadError::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let guard = &*ptr;
        guard.set_callback(cb)
    }));

    result.unwrap_or(QuadError::UnknownError)
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_consume_and_destroy(ptr: *mut QuadGuard) -> QuadError { unsafe {
    if ptr.is_null() {
        return QuadError::NullPointer;
    }
    
    let result = catch_unwind(AssertUnwindSafe(|| {
        // Preuzimamo vlasništvo nad Box-om i uništavamo ga, 
        // a ovde možete izvršiti dodatne "move" operacije nad unutrašnjim resursima
        let guard = Box::from_raw(ptr);
        
        // Primer provere stanja pre konačnog uništenja
        if let Ok(inner) = guard.inner.lock() {
            if inner.current_state == QuadState::Lockdown {
                // Možemo izvršiti dodatne bezbednosne radnje pre brisanja
            }
        }
        
        drop(guard);
        QuadError::Ok
    }));

    result.unwrap_or(QuadError::UnknownError)
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_set_threshold(
    ptr: *mut QuadGuard,
    threshold: u32,
) -> QuadError { unsafe {
    if ptr.is_null() {
        return QuadError::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let guard = &*ptr;
        guard.set_threshold(threshold)
    }));

    result.unwrap_or(QuadError::UnknownError)
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_analyze(ptr: *mut QuadGuard) -> QuadState { unsafe {
    if ptr.is_null() {
        return QuadState::Nominal;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let guard = &*ptr;
        guard.analyze()
    }));

    result.unwrap_or(QuadState::Nominal)
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_clone_ref(ptr: *const QuadGuard) -> *mut QuadGuard { unsafe {
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    
    let result = catch_unwind(AssertUnwindSafe(|| {
        // Rekonstruišemo referencu bez uništenja (uz poziv Arc::increment_strong_count u pozadini preko kloniranja)
        let guard_ref = &*ptr;
        let cloned_guard = Box::new(guard_ref.clone());
        Box::into_raw(cloned_guard)
    }));

    result.unwrap_or(std::ptr::null_mut())
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_get_last_error(ptr: *mut QuadGuard) -> QuadError { unsafe {
    if ptr.is_null() {
        return QuadError::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let guard = &*ptr;
        if let Ok(inner) = guard.inner.lock() {
            inner.last_error
        } else {
            QuadError::LockError
        }
    }));

    result.unwrap_or(QuadError::UnknownError)
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_terminate(ptr: *mut QuadGuard, pid: u32) -> QuadError { unsafe {
    if ptr.is_null() {
        return QuadError::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let guard = &*ptr;
        
        // Zaštita od samoubistva procesa
        #[cfg(target_os = "windows")]
        {
            if pid == crate::native_api::win_api::GetCurrentProcessId() {
                if let Ok(mut inner) = guard.inner.lock() {
                    inner.last_error = QuadError::SelfTerminationBlocked;
                }
                return QuadError::SelfTerminationBlocked;
            }
        }

        #[cfg(target_os = "linux")]
        {
            if pid as i32 == crate::native_api::linux_api::getpid() {
                if let Ok(mut inner) = guard.inner.lock() {
                    inner.last_error = QuadError::SelfTerminationBlocked;
                }
                return QuadError::SelfTerminationBlocked;
            }
        }

        // Gašenje procesa po OS-u
        #[cfg(target_os = "windows")]
        {
            use crate::native_api::win_api::*;
            let handle = OpenProcess(0x0001, 0, pid);
            if handle.is_null() {
                if let Ok(mut inner) = guard.inner.lock() {
                    inner.last_error = QuadError::AccessDenied;
                }
                return QuadError::AccessDenied;
            }

            let res = TerminateProcess(handle, 1);
            CloseHandle(handle);

            if res != 0 {
                if let Ok(mut inner) = guard.inner.lock() {
                    inner.last_error = QuadError::Ok;
                }
                QuadError::Ok
            } else {
                if let Ok(mut inner) = guard.inner.lock() {
                    inner.last_error = QuadError::UnknownError;
                }
                QuadError::UnknownError
            }
        }

        #[cfg(target_os = "linux")]
        {
            use crate::native_api::linux_api::*;
            let term_res = kill(pid as i32, 15); // SIGTERM
            if term_res == 0 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                if kill(pid as i32, 0) != 0 {
                    if let Ok(mut inner) = guard.inner.lock() {
                        inner.last_error = QuadError::Ok;
                    }
                    return QuadError::Ok;
                }
            }

            let kill_res = kill(pid as i32, 9); // SIGKILL
            if kill_res == 0 {
                if let Ok(mut inner) = guard.inner.lock() {
                    inner.last_error = QuadError::Ok;
                }
                QuadError::Ok
            } else {
                if let Ok(mut inner) = guard.inner.lock() {
                    inner.last_error = QuadError::AccessDenied;
                }
                QuadError::AccessDenied
            }
        }
    }));

    result.unwrap_or(QuadError::UnknownError)
}}

/// Increments the underlying `Arc` reference count and returns a new owned raw pointer
/// that must also be freed independently by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_clone_handle(ptr: *const QuadGuard) -> *mut QuadGuard {
    if ptr.is_null() {
        return ptr::null_mut();
    }

    let res = catch_unwind(AssertUnwindSafe(|| unsafe {
        let guard = &*ptr;
        Box::into_raw(Box::new(guard.clone()))
    }));

    res.unwrap_or(ptr::null_mut())
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QuadCabiSnapshot {
    pub current_state_bits: u8, // 0b00..=0b11
    pub packed_lanes_u8: u8,    // 4 x 2-bit states packed in 1 byte (75% savings)
    pub ram_threshold: u32,
    pub cpu_threshold: u32,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_read_snapshot(
    ptr: *const QuadGuard,
    out_snap: *mut QuadCabiSnapshot,
) -> i32 {
    if ptr.is_null() || out_snap.is_null() {
        return -1; // NullPointer
    }

    let res = catch_unwind(AssertUnwindSafe(|| unsafe {
        let guard = &*ptr;
        let Ok(inner) = guard.inner.lock() else {
            return -5; // LockError
        };

        *out_snap = QuadCabiSnapshot {
            current_state_bits: inner.current_state.to_bits() & 0b11,
            packed_lanes_u8: inner.current_state.to_bits() & 0b11,
            ram_threshold: inner.ram_threshold,
            cpu_threshold: inner.cpu_threshold,
        };
        0 // Ok
    }));

    res.unwrap_or(-99) // UnknownError
}