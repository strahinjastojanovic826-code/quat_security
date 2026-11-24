# 🛡️ Quad_security Security Core

> **A high-performance, zero-dependency Rust telemetry engine for real-time threat evaluation & system monitoring.**

---

## ⚡ Overview

**Quad_security Security Core** is a lightweight system telemetry engine engineered in pure **Rust**. Designed to operate with **zero third-party crates**, it interfaces directly with low-level kernel APIs on **Windows** and virtual filesystems on **Linux** to drive a deterministic, 4-state system health model.

---

## 🔑 Key Features

- **2-Bit Quad-State Security Architecture:** Highly efficient 4-state engine using compact 2-bit evaluation:
  - `Nominal` (`0b00`) – Standard baseline operations[cite: 40].
  - `Elevated` (`0b01`) – Anomalous activity detected; telemetry sampling scaled up[cite: 40].
  - `Critical` (`0b10`) – High-risk threshold breached; containment protocols triggered[cite: 40].
  - `Lockdown` (`0b11`) – Emergency state enforcement and process isolation[cite: 40].
- **🔒 Thread-Safe & Atomic State Synchronization:** Built with `Arc<Mutex<QuadGuardInner>>` and lock-free atomic primitives for secure execution across concurrent OS threads[cite: 40].
- **🖥️ Native Cross-Platform OS Inspection:** 
  - **Windows:** Queries memory and process subsystem status via raw `kernel32.dll` FFI bindings[cite: 40].
  - **Linux:** Inspects live process metrics directly via high-speed `/proc` virtual filesystem parsing[cite: 40].
  - **macOS:** System inspection utilizing Mach kernel API and `sysctl` for Apple platforms.
- **📊 Advanced Multivariate Metrics:** Tracks real-time RAM, CPU, I/O wait, Network load (`network_load_pct`), and GPU temperature (`gpu_temp_celsius`) to compute weighted threat scores[cite: 1].
- **📈 Hysteresis State Machine:** Prevents rapid state oscillation (*flapping*) using dedicated high and low evaluation thresholds[cite: 6, 7].
- **🌐 Multi-Language C-ABI Export:** Features un-mangled `#[no_mangle]` C calling conventions (`cdylib`) for seamless integration with C++, C# (.NET), Python, and Go[cite: 40].
- **🛡️ Embedded Self-Termination Guard:** Prevents malicious or accidental self-kill signals against the security monitoring process[cite: 40].
- **🔄 Circular Event History Tracking:** Tracks the last 10 state transitions with precise timestamps and `QuadReason` diagnostics[cite: 6, 7, 8, 12, 40].
- **🚀 Dynamic Action & Webhook Plug-in System:** Automatically triggers local shell scripts or HTTP webhook payloads upon security state escalations.
- **⚡ FFI Panic Safety & Unwind Protection:** Robust FFI boundary protection using `std::panic::catch_unwind` and `AssertUnwindSafe` to prevent Rust panics from unwinding across foreign language boundaries[cite: 2, 40].
- **🔔 Asynchronous State Callbacks:** Support for registering C-compatible callback functions to instantly notify external systems when a security state change occurs[cite: 6, 7, 40].
- **Quaternary Byte Packing (`QuadPack4`):** Packs four 2-bit quaternary states into a single `u8` byte (up to 75% state memory reduction) with safe fallback handling for invalid bit patterns.
- **Policy-Driven Hysteresis & Reason Codes:** Connects `SecurityPolicy` thresholds directly with `HysteresisEvaluator` and standardized `QuadReason` transition variants (`None`, `ResourceThreshold`, `ThreatEscalation`, `LockdownPolicy`).
- **Safe Action Executor & Policy Guards:** Enforces execution policies and input validation before triggering external actions or webhooks to mitigate shell/command injection risks.
- **Extended FFI Handle Cloning & Snapshots:** Supports handle cloning (`quad_guard_clone_handle`) and safe C-ABI snapshot reads (`quad_guard_read_snapshot`) alongside standard lifecycle management.

---

## Benchmark results

| Benchmark / Test Case | Measured Time | Category | Notes / Scope |
| :--- | :--- | :--- | :--- |
| **Invalid bits fallback resolution** (`test_invalid_bits_fallback`) | `200ns`[cite: 22] | State / Fallback | Safe fallback resolution for out-of-range/invalid bit patterns[cite: 22] |
| **FFI Null-pointer check overhead** (`test_ffi_null_pointer_safety`) | `400ns`[cite: 22] | FFI Safety | Null pointer guard validation across C-ABI entry points[cite: 22] |
| **Hysteresis from_policy evaluation** (`test_hysteresis_from_policy_thresholds`) | `400ns`[cite: 22] | Policy / Hysteresis | Threshold construction and state evaluation from `SecurityPolicy`[cite: 22] |
| **Bit packing and byte shifting** (`test_quad_bit_packing_and_shifting`) | `400ns`[cite: 22] | Quaternary Logic | 2-bit state extraction and byte-level bit-shifting operations[cite: 22] |
| **QuadPack4 lane set/get (1 byte)** (`test_quad_pack4_four_lanes_in_one_byte`) | `400ns`[cite: 22] | Memory Optimization | Packing and reading 4 quaternary states inside a single `u8`[cite: 22] |
| **Hysteresis transition evaluation** (`test_hysteresis_state_transitions`) | `600ns`[cite: 22] | State Machine | Hysteresis state transition checks across threat levels[cite: 22] |
| **Initialization latency** (`test_quad_guard_initialization`) | `1µs`[cite: 22] | Core Lifecycle | Creating a new `QuadGuard` instance and verifying initial state[cite: 22] |
| **Callback execution latency** (`test_callback_execution`) | `1.3µs`[cite: 22] | Event / Callback | Invoking registered state-change callback on transition[cite: 22] |
| **Threshold validation speed** (`test_threshold_boundary_and_validation`) | `1.5µs`[cite: 22] | Guard Config | Validating and clamping threshold boundary values[cite: 22] |
| **Multivariate threat score calc speed** (`test_extended_metrics_and_threat_score`) | `2.5µs`[cite: 22] | Telemetry / Scoring | Computing multivariate threat score from system metrics[cite: 22] |
| **Self-termination check latency** (`test_self_termination_guard`) | `3.3µs`[cite: 22] | Process Protection | Checking and blocking self-termination attempts via FFI[cite: 22] |
| **FFI clone handle & snapshot read** (`test_ffi_clone_handle_and_snapshot`) | `3.6µs`[cite: 22] | FFI / Snapshot | Cloning FFI handle and reading snapshot data[cite: 22] |
| **History Ring-Buffer stress** (`test_stress_history_overflow`) | `25µs`[cite: 22] | History Buffer | 100 state transitions stressing the bounded history ring-buffer[cite: 22] |
| **FFI Full lifecycle duration** (`test_ffi_full_lifecycle`) | `35µs`[cite: 22] | FFI Lifecycle | End-to-end `new`, configure, callback, analyze, and `free` cycle[cite: 22] |
| **Security policy load & fallback speed** (`test_security_policy_defaults_and_fallback`) | `92.9µs`[cite: 22] | Policy I/O | Policy loading attempt (including missing-file fallback to defaults)[cite: 22] |
| **Multithreaded concurrent access (10 threads)** (`test_multithreaded_concurrent_access`) | `1.281ms`[cite: 22] | Concurrency | Concurrent threshold updates and analysis across 10 threads[cite: 22] |
| **Action executor trigger overhead** (`test_action_executor_safety`) | `3.5583ms`[cite: 22] | Action Execution | Action executor trigger path and safety policy enforcement[cite: 22] |

---

## 💻 Usage & Integration Example

### Rust Integration (`main.rs`)

Add Quad-Guard as a dependency or use it as an internal library module:

```rust
use quat_security::{QuadGuard, QuadState, SystemMetrics};

fn main() {
    println!("=== === QUAD-SECURITY ENGINE DEMO === ===");

    // 1. Inicijalizacija garda
    let guard = QuadGuard::new();

    // Čitanje trenutnog stanja preko Mutex-a
    {
        let inner = guard.inner.lock().unwrap();
        println!("Initial state: {:?}", inner.current_state);
    }

    // Registracija C-compatible callback-a za dojave
    guard.set_callback(Some(on_state_change)).ok();

    // 2. Podešavanje praga memorije na 75%
    guard.set_threshold(75).ok();
    println!("RAM threshold updated to 75%");

    // 3. Multivarijatna analiza sa novim metrikama (RAM, CPU, I/O, Network, GPU Temp)
    println!("\n--- 3.1. Advanced Multivariate System Analysis ---");
    let metrics = SystemMetrics::new(78, 65, 30, 85, 88);
    let threat_score = metrics.calculate_threat_score();
    println!("Calculated Multivariate Threat Index: {}/100", threat_score);

    let evaluated_state = guard.analyze_multivariate(metrics);
    println!("Resulting Quad-State after multivariate evaluation: {:?}", evaluated_state);

    // 4. Test C-ABI zaštite od samogašenja (Self-termination protection)
    #[cfg(target_os = "windows")]
    let current_pid = unsafe { quat_security::native_api::win_api::GetCurrentProcessId() };

    #[cfg(target_os = "linux")]
    let current_pid = unsafe { quat_security::native_api::linux_api::getpid() as u32 };

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let current_pid = 1234; // Fallback za ostale sisteme

    println!("\nAttempting self-termination on PID: {}...", current_pid);
    
    unsafe {
        // Alociramo FFI objekat radi testiranja C API-ja
        let guard_ptr = quad_guard_new();

        let result = quad_guard_terminate(guard_ptr, current_pid);
        match result {
            quat_security::QuadError::SelfTerminationBlocked => {
                println!("SUCCESS: Engine correctly blocked self-termination!");
            }
            other => {
                println!("Unexpected result: {:?}", other);
            }
        }

        // Oslobađamo FFI memoriju
        quad_guard_free(guard_ptr);
    }

    // 5. Pregled povijesti događaja
    let inner = guard.inner.lock().unwrap();
    println!("\nRecorded transition events count: {}", inner.history_count);
    println!("Last engine error status: {:?}", inner.last_error);

    println!("\n=== DEMO COMPLETED SUCCESSFULLY ===");
}

// Definicija callback funkcije za obaveštenja o promeni stanja
extern "C" fn on_state_change(prev: QuadState, new: QuadState, reason: quat_security::QuadReason) {
    println!("[CALLBACK] State transitioned from {:?} to {:?} due to reason: {:?}", prev, new, reason);
}
```

---

### Quaternary Packing & FFI Handle Cloning Example

```rust
use quat_security::ffi::{
    quad_guard_clone_handle, quad_guard_free, quad_guard_new, quad_guard_read_snapshot,
    QuadCabiSnapshot,
};
use quat_security::state::{QuadPack4, QuadState};

fn main() {
    // 1. Pack 4 subsystem states (2 bits each: 00, 01, 10, 11) into a single byte
    let mut pack = QuadPack4::new();
    pack.set(0, QuadState::Nominal);
    pack.set(1, QuadState::Elevated);
    pack.set(2, QuadState::Critical);
    pack.set(3, QuadState::Lockdown);

    assert_eq!(pack.get(2), QuadState::Critical);

    // 2. Clone FFI handle and read snapshot safely
    unsafe {
        let primary = quad_guard_new();
        let cloned = quad_guard_clone_handle(primary);

        let mut snap = QuadCabiSnapshot {
            current_state_bits: 0,
            packed_lanes_u8: 0,
            ram_threshold: 0,
            cpu_threshold: 0,
        };
        let status = quad_guard_read_snapshot(cloned, &mut snap);
        assert_eq!(status, 0);

        quad_guard_free(cloned);
        quad_guard_free(primary);
    }
}
```

---

```

## 🛠️ Quick Start

### 1. Execute Embedded Test Suite
Run internal test cases and telemetry simulations:
cargo run

### 2. Compile Shared Library
Build optimized dynamic shared objects (`.dll` for Windows, `.so` for Linux):
cargo build --release

### 3. Results
cargo test -- --nocapture

*Outputs are available in `target/release/`.*

---

```
## 🪢 C-ABI Interface

Below are the exported native functions available for host integration:

| Function | Return Type | Description |
| :--- | :--- | :--- |
| `quad_security_new()` | `*mut QuadGuard` | Heap-allocates and returns a fresh engine instance |
| `quad_security_analyze(ptr)` | `QuadState` | Triggers a telemetry pass and returns active state |
| `quad_security_terminate(ptr, pid)` | `i32` | Initiates process isolation/termination for target PID |
| `quad_security_free(ptr)` | `void` | Safely deallocates engine resources from memory |

---

```
## 🔬 Purpose & Disclaimer

This library is an experimental research prototype aimed at exploring low-level security telemetry techniques in Rust. It is intended strictly for educational, testing, and research applications.

## Integration Examples (C, C++, C#)

The `quat_security` library provides a native **C-ABI** interface (`cdylib`), making it compatible with C, C++, and C# (.NET).
```

---

### 1. C Example

Include the generated `quat_security.h` header file and link against the compiled library (`quat_security.dll` on Windows or `libquat_security.so` on Linux).

```c
#include <stdio.h>
#include "quat_security.h"

int main(void) {
    // Initialize the QuadGuard instance
    QuadGuard* guard = quad_guard_new();
    if (!guard) {
        printf("Failed to create QuadGuard instance.\n");
        return 1;
    }

    // Set RAM threshold to 75%
    quad_guard_set_threshold(guard, 75);

    // Perform system analysis
    QuadState state = quad_guard_analyze(guard);
    printf("Current Guard State: %d\n", state);

    // Free allocated memory
    quad_guard_free(guard);
    return 0;
}
```

---

### Additional C Example: Handle Cloning & Snapshot

```c
#include <stdint.h>
#include <stdio.h>
#include "quat_security.h"

int run_clone_and_snapshot_demo(void) {
    QuadGuard* primary = quad_guard_new();
    if (!primary) {
        return 1;
    }

    QuadGuard* cloned = quad_guard_clone_handle(primary);
    if (!cloned) {
        quad_guard_free(primary);
        return 1;
    }

    QuadCabiSnapshot snap = {0};
    int status = quad_guard_read_snapshot(cloned, &snap);
    if (status == 0) {
        printf("Snapshot state bits: %u, packed lanes: 0x%02X\n",
               (unsigned)snap.current_state_bits,
               (unsigned)snap.packed_lanes_u8);
    }

    quad_guard_free(cloned);
    quad_guard_free(primary);
    return 0;
}
```

---


### 2. C++ Example

You can seamlessly use the library in C++ within a class or namespace wrapper.

```cpp
#include <iostream>
#include "quat_security.h"

class SecurityGuard {
private:
    QuadGuard* instance;

public:
    SecurityGuard(uint32_t threshold = 80) {
        instance = quad_guard_new();
        if (instance) {
            quad_guard_set_threshold(instance, threshold);
        }
    }

    ~SecurityGuard() {
        if (instance) {
            quad_guard_free(instance);
        }
    }

    QuadState analyze() {
        return instance ? quad_guard_analyze(instance) : Nominal;
    }
};

int main() {
    SecurityGuard guard(85);
    QuadState state = guard.analyze();

    std::cout << "Analysis Result State Code: " << static_cast<int>(state) << std::endl;
    return 0;
}
```

---

### 3. C# (.NET) Example

Use **Platform Invoke (P/Invoke)** to import functions from the compiled dynamic library (`quat_security.dll` / `libquat_security.so`).

```csharp
using System;
using System.Runtime.InteropServices;

namespace SecurityIntegration
{
    public enum QuadState : byte
    {
        Nominal = 0,
        Elevated = 1,
        Critical = 2,
        Lockdown = 3
    }

    public enum QuadError : int
    {
        Ok = 0,
        NullPointer = -1,
        AccessDenied = -2,
        InvalidPid = -3,
        SelfTerminationBlocked = -4,
        LockError = -5,
        UnknownError = -99
    }

    class Program
    {
        private const string DllName = "quat_security";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr quad_guard_new();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void quad_guard_free(IntPtr ptr);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern QuadError quad_guard_set_threshold(IntPtr ptr, uint threshold);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern QuadState quad_guard_analyze(IntPtr ptr);

        static void Main()
        {
            IntPtr guard = quad_guard_new();
            if (guard == IntPtr.Zero)
            {
                Console.WriteLine("Failed to instantiate QuadGuard.");
                return;
            }

            quad_guard_set_threshold(guard, 80);
            QuadState state = quad_guard_analyze(guard);

            Console.WriteLine($"Current State: {state}");

            quad_guard_free(guard);
        }
    }
}
``` 

---

## 📄 License & Commercial Licensing

This project is dual-licensed:

- **Open Source (AGPL-3.0):** Available under the [GNU Affero General Public License v3.0](./LICENSE) for open-source projects, education, and non-commercial research.
- **Commercial License:** If you wish to integrate `quat_security` into proprietary software without the viral requirements of AGPL-3.0, custom commercial licenses are available.

For commercial licensing inquiries or enterprise support, please contact: `strahinjastojanovic826@gmail.com`