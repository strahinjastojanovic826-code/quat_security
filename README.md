# 🛡️ Quad_security Security Core

> **A high-performance, zero-dependency Rust telemetry engine for real-time threat evaluation & system monitoring.**

> **v1.0.0 Release Note:** Major release featuring thread-safe engine architecture (`Arc<Mutex>`), 2-bit quad-state memory optimizations, and stable C-ABI support for C, C++, and C# (.NET).

---

## ⚡ Overview

**Quad_security Security Core** is a lightweight system telemetry engine engineered in pure **Rust**. Designed to operate with **zero third-party crates**, it interfaces directly with low-level kernel APIs on **Windows** and virtual filesystems on **Linux** to drive a deterministic, 4-state system health model.

---

## 🔑 Key Features

- **🎛️ 2-Bit Quad-State Security Architecture:** Highly efficient 4-state engine using compact 2-bit quats (`0b00` to `0b11`) for dynamic threat evaluation:
  - `Nominal` (`0b00`) — Standard baseline operations.
  - `Elevated` (`0b01`) — Anomalous activity detected; telemetry sampling scaled up.
  - `Critical` (`0b10`) — High-risk threshold breached; containment protocols triggered.
  - `Lockdown` (`0b11`) — Emergency state enforcement and process isolation.

- **🔒 Thread-Safe & Atomic State Synchronization:** Built with `Arc<Mutex<QuadGuardInner>>` and lock-free atomic primitives to ensure reliable execution across concurrent OS threads.

- **⚡ Zero External Dependencies:** Built strictly using the Rust Standard Library (`std`), eliminating supply chain vulnerability risks and external crate overhead.

- **💻 Native Cross-Platform OS Inspection:**
  - **Windows:** Queries memory and process subsystem status via raw `kernel32.dll` FFI bindings.
  - **Linux:** Inspects live process metrics directly via high-speed `/proc` virtual filesystem parsing.

- **🌐 Multi-Language C-ABI Export:** Features un-mangled `#[no_mangle]` C calling conventions (`cdylib`) for seamless native integration into **C**, **C++**, **C# (.NET)**, **Python**, and **Go**.

- **🛡️ Embedded Self-Termination Guard:** Prevents malicious or accidental self-kill signals against the security engine process.

---

## 📂 Project Structure

quat_security/
├── Cargo.toml      # Package definition & C-dylib config
└── src/
    └── lib.rs      # Core engine logic, native FFI & C-ABI exports

---

💻 Usage & Integration Example
Rust Integration (main.rs)

Add Quad-Guard as a dependency or use it as an internal library module:

```rust
use quat_security::{
    quad_guard_free, quad_guard_new, quad_guard_terminate,
    QuadError, QuadGuard, QuadReason, QuadState,
};

// Definiramo C-kompatibilan callback koji reagira na promjene stanja
extern "C" fn on_state_change(prev: QuadState, new_state: QuadState, reason: QuadReason) {
    println!(
        "[EVENT LOG] State changed from {:?} to {:?} | Reason: {:?}",
        prev, new_state, reason
    );
}

fn main() {
    println!("=== QUAD-SECURITY ENGINE DEMO ===");

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

    // 3. Analiza stanja sistema
    let current_state = guard.analyze();
    println!("System analysis result: {:?}", current_state);

    // 4. Test C-ABI zaštite od samogašenja (Self-termination protection)
    #[cfg(target_os = "windows")]
    let current_pid = unsafe { quat_security::native_api::win_api::GetCurrentProcessId() };

    #[cfg(target_os = "linux")]
    let current_pid = unsafe { quat_security::native_api::linux_api::getpid() as u32 };

    println!("Attempting self-termination on PID: {}...", current_pid);

    unsafe {
        // Alociramo FFI objekat radi testiranja C API-ja
        let guard_ptr = quad_guard_new();

        let result = quad_guard_terminate(guard_ptr, current_pid);
        match result {
            QuadError::SelfTerminationBlocked => {
                println!("SUCCESS: Engine correctly blocked self-termination!");
            }
            other => println!("Unexpected result: {:?}", other),
        }

        // Oslobađamo FFI memoriju
        quad_guard_free(guard_ptr);
    }

    // 5. Pregled povijesti događaja
    {
        let inner = guard.inner.lock().unwrap();
        println!("\nRecorded transition events: {}", inner.history_count);
        println!("Last engine error status: {:?}", inner.last_error);
    }

    println!("=== DEMO COMPLETED SUCCESSFULLY ===");
}
```

---

## 🛠️ Quick Start

### 1. Execute Embedded Test Suite
Run internal test cases and telemetry simulations:
cargo run

### 2. Compile Shared Library
Build optimized dynamic shared objects (`.dll` for Windows, `.so` for Linux):
cargo build --release

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