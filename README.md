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

---

## Benchmark results

| Operation / Test | Measured Time |
| :--- | :--- |
| **Invalid bits fallback resolution** | 200 ns |
| **Hysteresis transition evaluation** | 300 ns |
| **FFI Null-pointer check overhead** | 300 ns |
| **Bit packing and byte shifting** | 400 ns |
| **Initialization latency** | 1.1 µs |
| **Threshold validation speed** | 1.3 µs |
| **Multivariate threat score calc speed** | 2 µs |
| **Self-termination check latency** | 2.8 µs |
| **Callback execution latency** | 4.5 µs |
| **History Ring-Buffer stress** | 16.3 µs |
| **FFI Full lifecycle duration** | 23 µs |
| **Security policy load & fallback speed** | 57.6 µs |
| **Multithreaded concurrent access (10 threads)** | 1.577 ms |
| **Action executor trigger overhead** | 3.1927 ms |

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