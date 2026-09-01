# 🛡️ Quad_security Security Core

> **A high-performance, zero-dependency Rust telemetry engine for real-time threat evaluation & system monitoring.**

---

## ⚡ Overview

**Quad_security Security Core** is a lightweight system telemetry engine engineered in pure **Rust**. Designed to operate with **zero third-party crates**, it interfaces directly with low-level kernel APIs on **Windows** and virtual filesystems on **Linux** to drive a deterministic, 4-state system health model.

---

## 🔥 Key Features

- **🛡️ 4-State Security Pipeline:** Dynamic state transitions designed for proactive threat response:
  - `Nominal` — Standard baseline operations.
  - `Elevated` — Anomalous activity detected; telemetry sampling scaled up.
  - `Critical` — High-risk threshold breached; containment protocols triggered.
  - `Lockdown` — Emergency state enforcement and process isolation.

- **🚀 Zero External Dependencies:** Built strictly using the Rust Standard Library (`std`), eliminating supply chain vulnerabilities and bloat.

- **💻 Native Cross-Platform Engine:**
  - **Windows:** Queries memory and process subsystem status via raw `kernel32.dll` FFI interfaces.
  - **Linux:** Inspects live process metrics directly via high-speed `/proc` virtual filesystem parsing.

- **🔗 Multi-Language C-ABI Export:** Features un-mangled `#[no_mangle]` C calling conventions for seamless integration into **C**, **C++**, **Python**, or **Go** runtime environments.

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

use quat_security::{QuadGuard, QuadState};

fn main() {
    // Initialize the Quad-Guard security engine
    let mut guard = QuadGuard::new();

    // Perform a system telemetry analysis pass
    let current_state = guard.analyze();

    match current_state {
        QuadState::Nominal => println!("[+] System operating normally."),
        QuadState::Elevated => println!("[!] Anomalous activity detected. Increasing telemetry sampling."),
        QuadState::Critical => println!("[WARN] Critical risk threshold reached! Containment pending."),
        QuadState::Lockdown => println!("[ALERT] Emergency Lockdown active! Isolating threats."),
    }

    // Isolate or terminate a target process if required
    let target_pid = 1234;
    if guard.should_terminate(target_pid) {
        let result = guard.terminate_process(target_pid);
        println!("[+] Process {} termination result: {}", target_pid, result);
    }
}

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

## 🪢 C-ABI Interface

Below are the exported native functions available for host integration:

| Function | Return Type | Description |
| :--- | :--- | :--- |
| `quad_security_new()` | `*mut QuadGuard` | Heap-allocates and returns a fresh engine instance |
| `quad_security_analyze(ptr)` | `QuadState` | Triggers a telemetry pass and returns active state |
| `quad_security_terminate(ptr, pid)` | `i32` | Initiates process isolation/termination for target PID |
| `quad_security_free(ptr)` | `void` | Safely deallocates engine resources from memory |

---

## 🔬 Purpose & Disclaimer

This library is an experimental research prototype aimed at exploring low-level security telemetry techniques in Rust. It is intended strictly for educational, testing, and research applications.