use std::panic::{catch_unwind, AssertUnwindSafe};
use crate::errors::QuadError;
use crate::guard::{QuadGuard, StateChangeCallback};
use crate::state::QuadState;

#[no_mangle]
pub unsafe extern "C" fn quad_guard_new() -> *mut QuadGuard {
    let result = catch_unwind(|| {
        Box::into_raw(Box::new(QuadGuard::new()))
    });
    result.unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn quad_guard_free(ptr: *mut QuadGuard) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(ptr));
    }));
}

#[no_mangle]
pub unsafe extern "C" fn quad_guard_set_callback(
    ptr: *mut QuadGuard,
    cb: Option<StateChangeCallback>,
) -> QuadError {
    if ptr.is_null() {
        return QuadError::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let guard = &*ptr;
        guard.set_callback(cb)
    }));

    result.unwrap_or(QuadError::UnknownError)
}

#[no_mangle]
pub unsafe extern "C" fn quad_guard_set_threshold(
    ptr: *mut QuadGuard,
    threshold: u32,
) -> QuadError {
    if ptr.is_null() {
        return QuadError::NullPointer;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let guard = &*ptr;
        guard.set_threshold(threshold)
    }));

    result.unwrap_or(QuadError::UnknownError)
}

#[no_mangle]
pub unsafe extern "C" fn quad_guard_analyze(ptr: *mut QuadGuard) -> QuadState {
    if ptr.is_null() {
        return QuadState::Nominal;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let guard = &*ptr;
        guard.analyze()
    }));

    result.unwrap_or(QuadState::Nominal)
}

#[no_mangle]
pub unsafe extern "C" fn quad_guard_get_last_error(ptr: *mut QuadGuard) -> QuadError {
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
}

#[no_mangle]
pub unsafe extern "C" fn quad_guard_terminate(ptr: *mut QuadGuard, pid: u32) -> QuadError {
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
}