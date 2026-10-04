/*
 * QUAD-GUARD SECURITY TELEMETRY CORE v0.2.0
 * 4-State Biological Model | Zero-Dependency
 * Cross-Platform: Windows, Linux & C-ABI Support
 */

pub mod errors;
pub mod ffi;
pub mod guard;
pub mod native_api;
pub mod state;

// Re-export za lakše korišćenje u Rust kodu
pub use errors::QuadError;
pub use ffi::*;
pub use guard::QuadGuard;
pub use state::{QuadState, StateEvent};
use crate::state::QuadReason;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    static CALLBACK_TRIGGERED: AtomicBool = AtomicBool::new(false);

    extern "C" fn mock_callback(_prev: QuadState, _new: QuadState, _reason: QuadReason) {
        CALLBACK_TRIGGERED.store(true, Ordering::SeqCst);
    }

    #[test]
    fn test_quad_guard_initialization() {
        let guard = QuadGuard::new();
        let inner = guard.inner.lock().unwrap();

        assert_eq!(inner.current_state, QuadState::Nominal);
        assert_eq!(inner.ram_threshold, 80);
        assert_eq!(inner.history_count, 0);
        assert_eq!(inner.last_error, QuadError::Ok);
    }

    #[test]
    fn test_stress_history_overflow() {
        let guard = QuadGuard::new();

        for i in 0..100 {
            let next = if i % 2 == 0 {
                QuadState::Elevated
            } else {
                QuadState::Nominal
            };

            let mut inner = guard.inner.lock().unwrap();
            QuadGuard::record_transition_with_reason(
                &mut inner,
                next,
                QuadReason::MemoryThresholdExceeded,
            );
        }

        let inner = guard.inner.lock().unwrap();
        assert_eq!(inner.history_count, 10);
        assert_eq!(inner.current_state, QuadState::Nominal);
    }

    #[test]
    fn test_callback_execution() {
        let guard = QuadGuard::new();
        assert_eq!(guard.set_callback(Some(mock_callback)), QuadError::Ok);

        CALLBACK_TRIGGERED.store(false, Ordering::SeqCst);

        {
            let mut inner = guard.inner.lock().unwrap();
            QuadGuard::record_transition_with_reason(
                &mut inner,
                QuadState::Elevated,
                QuadReason::MemoryThresholdExceeded,
            );
        }

        assert!(CALLBACK_TRIGGERED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_ffi_null_pointer_safety() {
        unsafe {
            assert_eq!(
                quad_guard_set_threshold(std::ptr::null_mut(), 90),
                QuadError::NullPointer
            );
            assert_eq!(
                quad_guard_set_callback(std::ptr::null_mut(), Some(mock_callback)),
                QuadError::NullPointer
            );
            assert_eq!(
                quad_guard_get_last_error(std::ptr::null_mut()),
                QuadError::NullPointer
            );
            assert_eq!(
                quad_guard_terminate(std::ptr::null_mut(), 1234),
                QuadError::NullPointer
            );
            assert_eq!(
                quad_guard_analyze(std::ptr::null_mut()),
                QuadState::Nominal
            );
        }
    }

    #[test]
    fn test_self_termination_guard() {
        unsafe {
            let guard_ptr = quad_guard_new();
            assert!(!guard_ptr.is_null());

            #[cfg(target_os = "windows")]
            let current_pid = crate::native_api::win_api::GetCurrentProcessId();

            #[cfg(target_os = "linux")]
            let current_pid = crate::native_api::linux_api::getpid() as u32;

            let err = quad_guard_terminate(guard_ptr, current_pid);
            assert_eq!(err, QuadError::SelfTerminationBlocked);
            assert_eq!(
                quad_guard_get_last_error(guard_ptr),
                QuadError::SelfTerminationBlocked
            );

            quad_guard_free(guard_ptr);
        }
    }

    #[test]
    fn test_ffi_full_lifecycle() {
        unsafe {
            // 1. Alokacija preko FFI
            let guard_ptr = quad_guard_new();
            assert!(!guard_ptr.is_null());

            // 2. Postavljanje praga
            let err_threshold = quad_guard_set_threshold(guard_ptr, 75);
            assert_eq!(err_threshold, QuadError::Ok);

            // 3. Registracija callback-a
            let err_cb = quad_guard_set_callback(guard_ptr, Some(mock_callback));
            assert_eq!(err_cb, QuadError::Ok);

            // 4. Analiza
            let state = quad_guard_analyze(guard_ptr);
            assert!(state == QuadState::Nominal || state == QuadState::Elevated);

            // 5. Oslobađanje memorije
            quad_guard_free(guard_ptr);
        }
    }

    // ==========================================
    // NOVI TESTOVI KOJE JE POTREBNO DODATI
    // ==========================================

    #[test]
    fn test_quad_bit_packing_and_shifting() {
        // Test pretvaranja 2 bita u stanje
        assert_eq!(QuadState::from_bits(0b00), QuadState::Nominal);
        assert_eq!(QuadState::from_bits(0b01), QuadState::Elevated);
        assert_eq!(QuadState::from_bits(0b10), QuadState::Critical);
        assert_eq!(QuadState::from_bits(0b11), QuadState::Lockdown);

        // Test ekstrakcije kvata iz bajta (npr. bajt 0b11_10_01_00)
        let byte: u8 = 0b11_10_01_00;
        assert_eq!(QuadState::from_byte_shift(byte, 0), QuadState::Nominal);   // 0b00
        assert_eq!(QuadState::from_byte_shift(byte, 1), QuadState::Elevated);  // 0b01
        assert_eq!(QuadState::from_byte_shift(byte, 2), QuadState::Critical);  // 0b10
        assert_eq!(QuadState::from_byte_shift(byte, 3), QuadState::Lockdown);  // 0b11
    }

    #[test]
    fn test_multithreaded_concurrent_access() {
        let guard = QuadGuard::new();
        let mut handles = vec![];

        // Pokrećemo 10 niti koje paralelno menjaju prag i pozivaju analizu
        for i in 0..10 {
            let guard_clone = guard.clone();
            let handle = thread::spawn(move || {
                guard_clone.set_threshold(50 + i * 2);
                let _ = guard_clone.analyze();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let inner = guard.inner.lock().unwrap();
        assert!(inner.ram_threshold >= 50 && inner.ram_threshold <= 70);
    }
}