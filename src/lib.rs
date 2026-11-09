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
pub mod policy;
pub mod metrics;
pub mod hysteresis;
pub mod actions;

// Re-export za lakše korišćenje u Rust kodu
pub use errors::QuadError;
pub use ffi::*;
pub use guard::QuadGuard;
pub use state::{QuadState, StateEvent};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use crate::state::QuadReason;
    use crate::metrics::SystemMetrics;
    use crate::hysteresis::HysteresisEvaluator;
    use crate::policy::SecurityPolicy;

    static CALLBACK_TRIGGERED: AtomicBool = AtomicBool::new(false);

    extern "C" fn mock_callback(_prev: QuadState, _new: QuadState, _reason: QuadReason) {
        CALLBACK_TRIGGERED.store(true, Ordering::SeqCst);
    }

    #[test]
    fn test_quad_guard_initialization() {
        let start = std::time::Instant::now();
        let guard = QuadGuard::new();
        let inner = guard.inner.lock().unwrap();

        assert_eq!(inner.current_state, QuadState::Nominal);
        assert_eq!(inner.ram_threshold, 80);
        assert_eq!(inner.history_count, 0);
        assert_eq!(inner.last_error, QuadError::Ok);
        
        println!("[BENCHMARK] Initialization latency: {:?}", start.elapsed());
    }

    #[test]
    fn test_stress_history_overflow() {
        let start = std::time::Instant::now();
        let guard = QuadGuard::new();

        for i in 0..100 {
            let next = if i % 2 == 0 { QuadState::Elevated } else { QuadState::Nominal };
            let mut inner = guard.inner.lock().unwrap();
            QuadGuard::record_transition_with_reason(&mut inner, next, QuadReason::MemoryThresholdExceeded);
        }

        let inner = guard.inner.lock().unwrap();
        assert_eq!(inner.history_count, 10);
        assert_eq!(inner.current_state, QuadState::Nominal);
        
        println!("[BENCHMARK] History Ring-Buffer stress: {:?}", start.elapsed());
    }

    #[test]
    fn test_callback_execution() {
        let guard = QuadGuard::new();
        assert_eq!(guard.set_callback(Some(mock_callback)), QuadError::Ok);
        CALLBACK_TRIGGERED.store(false, Ordering::SeqCst);

        let start = std::time::Instant::now();
        let mut inner = guard.inner.lock().unwrap();
        QuadGuard::record_transition_with_reason(&mut inner, QuadState::Elevated, QuadReason::MemoryThresholdExceeded);
        assert!(CALLBACK_TRIGGERED.load(Ordering::SeqCst));
        
        println!("[BENCHMARK] Callback execution latency: {:?}", start.elapsed());
    }

    #[test]
    fn test_ffi_null_pointer_safety() {
        let start = std::time::Instant::now();
        unsafe {
            assert_eq!(quad_guard_set_threshold(std::ptr::null_mut(), 90), QuadError::NullPointer);
            assert_eq!(quad_guard_set_callback(std::ptr::null_mut(), Some(mock_callback)), QuadError::NullPointer);
            assert_eq!(quad_guard_get_last_error(std::ptr::null_mut()), QuadError::NullPointer);
            assert_eq!(quad_guard_terminate(std::ptr::null_mut(), 1234), QuadError::NullPointer);
            assert_eq!(quad_guard_analyze(std::ptr::null_mut()), QuadState::Nominal);
        }
        println!("[BENCHMARK] FFI Null-pointer check overhead: {:?}", start.elapsed());
    }

    #[test]
    fn test_self_termination_guard() {
        let start = std::time::Instant::now();
        unsafe {
            let guard_ptr = quad_guard_new();
            assert!(!guard_ptr.is_null());

            #[cfg(target_os = "windows")]
            let current_pid = crate::native_api::win_api::GetCurrentProcessId();
            #[cfg(target_os = "linux")]
            let current_pid = crate::native_api::linux_api::getpid() as u32;

            let err = quad_guard_terminate(guard_ptr, current_pid);
            assert_eq!(err, QuadError::SelfTerminationBlocked);
            assert_eq!(quad_guard_get_last_error(guard_ptr), QuadError::SelfTerminationBlocked);

            quad_guard_free(guard_ptr);
        }
        println!("[BENCHMARK] Self-termination check latency: {:?}", start.elapsed());
    }

    #[test]
    fn test_ffi_full_lifecycle() {
        let start = std::time::Instant::now();
        unsafe {
            let guard_ptr = quad_guard_new();
            assert!(!guard_ptr.is_null());

            let err_threshold = quad_guard_set_threshold(guard_ptr, 75);
            assert_eq!(err_threshold, QuadError::Ok);

            let err_cb = quad_guard_set_callback(guard_ptr, Some(mock_callback));
            assert_eq!(err_cb, QuadError::Ok);

            let state = quad_guard_analyze(guard_ptr);
            assert!(state == QuadState::Nominal || state == QuadState::Elevated);

            quad_guard_free(guard_ptr);
        }
        println!("[BENCHMARK] FFI Full lifecycle duration: {:?}", start.elapsed());
    }

    #[test]
    fn test_quad_bit_packing_and_shifting() {
        let start = std::time::Instant::now();
        assert_eq!(QuadState::from_bits(0b00), QuadState::Nominal);
        assert_eq!(QuadState::from_bits(0b01), QuadState::Elevated);
        assert_eq!(QuadState::from_bits(0b10), QuadState::Critical);
        assert_eq!(QuadState::from_bits(0b11), QuadState::Lockdown);

        let byte: u8 = 0b11_10_01_00;
        assert_eq!(QuadState::from_byte_shift(byte, 0), QuadState::Nominal);
        assert_eq!(QuadState::from_byte_shift(byte, 1), QuadState::Elevated);
        assert_eq!(QuadState::from_byte_shift(byte, 2), QuadState::Critical);
        assert_eq!(QuadState::from_byte_shift(byte, 3), QuadState::Lockdown);

        println!("[BENCHMARK] Bit packing and byte shifting: {:?}", start.elapsed());
    }

    #[test]
    fn test_multithreaded_concurrent_access() {
        let start = std::time::Instant::now();
        let guard = QuadGuard::new();
        let mut handles = vec![];

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

        println!("[BENCHMARK] Multithreaded concurrent access (10 threads): {:?}", start.elapsed());
    }

    #[test]
    fn test_threshold_boundary_and_validation() {
        let start = std::time::Instant::now();
        let guard = QuadGuard::new();

        let res_valid = guard.set_threshold(90);
        assert_eq!(res_valid, QuadError::Ok);

        let inner = guard.inner.lock().unwrap();
        assert_eq!(inner.ram_threshold, 90);
        drop(inner);

        let res_ignored = guard.set_threshold(150);
        assert_eq!(res_ignored, QuadError::Ok);

        let inner = guard.inner.lock().unwrap();
        assert_eq!(inner.ram_threshold, 90);

        println!("[BENCHMARK] Threshold validation speed: {:?}", start.elapsed());
    }

    #[test]
    fn test_invalid_bits_fallback() {
        let start = std::time::Instant::now();
        let state_overflow = QuadState::from_bits(0xFF);
        assert_eq!(state_overflow, QuadState::Lockdown);

        let reason_overflow = QuadReason::from_bits(0xFF);
        assert_eq!(reason_overflow, QuadReason::ProcessTerminationFailure);

        println!("[BENCHMARK] Invalid bits fallback resolution: {:?}", start.elapsed());
    }

    #[test]
    fn test_extended_metrics_and_threat_score() {
        let start = std::time::Instant::now();
        let metrics = SystemMetrics::new(75, 80, 40, 85, 90);
        let threat_score = metrics.calculate_threat_score();

        assert!(threat_score > 0);
        assert!(threat_score <= 100);

        println!("[BENCHMARK] Multivariate threat score calc speed: {:?}", start.elapsed());
    }

    #[test]
    fn test_action_executor_safety() {
        let start = std::time::Instant::now();
        crate::actions::ActionExecutor::trigger_external_action("Critical", 92, None);
        assert!(true);

        println!("[BENCHMARK] Action executor trigger overhead: {:?}", start.elapsed());
    }

    #[test]
    fn test_hysteresis_state_transitions() {
        let start = std::time::Instant::now();
        let evaluator = HysteresisEvaluator::default();

        let next_from_nominal = evaluator.evaluate_next_state(QuadState::Nominal, 80);
        assert_eq!(next_from_nominal, QuadState::Elevated);

        let next_from_critical = evaluator.evaluate_next_state(QuadState::Critical, 99);
        assert_eq!(next_from_critical, QuadState::Lockdown);

        let next_from_lockdown = evaluator.evaluate_next_state(QuadState::Lockdown, 50);
        assert_eq!(next_from_lockdown, QuadState::Critical);

        println!("[BENCHMARK] Hysteresis transition evaluation: {:?}", start.elapsed());
    }

    #[test]
    fn test_security_policy_defaults_and_fallback() {
        let start = std::time::Instant::now();
        let policy = SecurityPolicy::default();

        assert_eq!(policy.ram_threshold_elevated, 75);
        assert_eq!(policy.ram_threshold_critical, 90);
        assert_eq!(policy.cpu_threshold_critical, 85);
        assert!(policy.auto_lockdown_on_breach);

        let fallback_policy = SecurityPolicy::load_from_file("non_existent_policy_file_xyz.toml");
        assert_eq!(fallback_policy.ram_threshold_elevated, 75);

        println!("[BENCHMARK] Security policy load & fallback speed: {:?}", start.elapsed());
    }
}