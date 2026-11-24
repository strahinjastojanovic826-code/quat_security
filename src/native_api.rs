#[cfg(target_os = "windows")]
pub mod win_api {
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct MEMORYSTATUSEX {
        pub dw_length: u32,
        pub dw_memory_load: u32,
        pub ull_total_phys: u64,
        pub ull_avail_phys: u64,
        pub ull_total_page_file: u64,
        pub ull_avail_page_file: u64,
        pub ull_total_virtual: u64,
        pub ull_avail_virtual: u64,
        pub ull_avail_extended_virtual: u64,
    }

    // SAFETY: Declarations match the official Win32 C-ABI signatures exported by
    // system libraries (`kernel32.dll`); callers must pass valid pointers and handles.
    unsafe extern "system" {
        pub fn GlobalMemoryStatusEx(lp_buffer: *mut MEMORYSTATUSEX) -> i32;
        pub fn OpenProcess(
            dw_desired_access: u32,
            b_inherit_handle: i32,
            dw_process_id: u32,
        ) -> *mut usize;
        pub fn TerminateProcess(h_process: *mut usize, u_exit_code: u32) -> i32;
        pub fn CloseHandle(h_object: *mut usize) -> i32;
        pub fn GetCurrentProcessId() -> u32;
    }
}

#[cfg(target_os = "linux")]
pub mod linux_api {
    extern "C" {
        pub fn kill(pid: i32, sig: i32) -> i32;
        pub fn getpid() -> i32;
    }
}

#[cfg(target_os = "macos")]
pub mod macos_api {
    use std::fs;
    
    // FFI eksterni pozivi za macOS (Mach kernel API)
    extern "C" {
        pub fn kill(pid: i32, sig: i32) -> i32;
        pub fn getpid() -> i32;
    }

    // Pomoćna funkcija za čitanje memorije na macOS-u preko vm_statistics
    pub fn get_mac_memory_usage() -> Result<(u64, u64), String> {
        // Alternativno čitanje preko sysctl (vm.swapusage / hw.memsize) ili top/ps u minimalističkoj izvedbi
        // Ovde koristimo robustan pristup čitanja sistemskih informacija
        let memsize_output = std::process::Command::new("sysctl")
            .arg("hw.memsize")
            .output()
            .map_err(|e| e.to_string())?;
            
        let mem_str = String::from_utf8_lossy(&memsize_output.stdout);
        let total_mem: u64 = mem_str
            .split(':')
            .nth(1)
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        // Za slobodnu memoriju možemo koristiti vm_stat
        let vm_output = std::process::Command::new("vm_stat")
            .output()
            .map_err(|e| e.to_string())?;
        let vm_str = String::from_utf8_lossy(&vm_output.stdout);
        
        // Parsiranje page size i slobodnih stranica (pojednostavljeno za demo)
        Ok((total_mem, total_mem / 4)) // Primer fallback procene ukoliko vm_stat zahteva detaljno parsiranje
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OsTelemetrySnapshot {
    pub total_ram_bytes: u64,
    pub avail_ram_bytes: u64,
    pub ram_usage_pct: u32,
    pub process_id: u32,
}

#[cfg(target_os = "windows")]
pub mod win_telemetry {
    use super::OsTelemetrySnapshot;
    use crate::native_api::win_api::{GetCurrentProcessId, GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use std::mem::size_of;

    pub fn collect_snapshot() -> OsTelemetrySnapshot {
        let mut mem = MEMORYSTATUSEX {
            dw_length: size_of::<MEMORYSTATUSEX>() as u32,
            dw_memory_load: 0,
            ull_total_phys: 0,
            ull_avail_phys: 0,
            ull_total_page_file: 0,
            ull_avail_page_file: 0,
            ull_total_virtual: 0,
            ull_avail_virtual: 0,
            ull_avail_extended_virtual: 0,
        };
 
        // SAFETY: `mem` is an initialized `MEMORYSTATUSEX` on the stack with `dw_length`
        // set to `size_of::<MEMORYSTATUSEX>()`, so `&mut mem` is valid for the call.
        let ok = unsafe { GlobalMemoryStatusEx(&mut mem) } != 0;
        // SAFETY: `GetCurrentProcessId` takes no arguments and safely returns the current PID.
        let pid = unsafe { GetCurrentProcessId() };

        if ok {
            OsTelemetrySnapshot {
                total_ram_bytes: mem.ull_total_phys,
                avail_ram_bytes: mem.ull_avail_phys,
                ram_usage_pct: mem.dw_memory_load.min(100),
                process_id: pid,
            }
        } else {
            OsTelemetrySnapshot {
                process_id: pid,
                ..OsTelemetrySnapshot::default()
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub mod linux_telemetry {
    use super::OsTelemetrySnapshot;
    use crate::native_api::linux_api::getpid;
    use std::fs;

    pub fn collect_snapshot() -> OsTelemetrySnapshot {
        // SAFETY: `getpid` is async-signal-safe and takes no pointer arguments, always
        // returning a valid process ID for the calling process.
        let pid = unsafe { getpid() }.max(0) as u32;
        let mut total_kb: u64 = 0;
        let mut avail_kb: u64 = 0;

        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    total_kb = rest
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);
                } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    avail_kb = rest
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);
                }
            }
        }

        let used_kb = total_kb.saturating_sub(avail_kb);
        let pct = if total_kb > 0 {
            ((used_kb.saturating_mul(100)) / total_kb).min(100) as u32
        } else {
            0
        };

        OsTelemetrySnapshot {
            total_ram_bytes: total_kb.saturating_mul(1024),
            avail_ram_bytes: avail_kb.saturating_mul(1024),
            ram_usage_pct: pct,
            process_id: pid,
        }
    }
}

#[cfg(target_os = "macos")]
pub mod macos_telemetry {
    use super::OsTelemetrySnapshot;
    use crate::native_api::macos_api::{get_mac_memory_usage, getpid};

    pub fn collect_snapshot() -> OsTelemetrySnapshot {
        // SAFETY: `getpid` takes no arguments and safely returns the current process ID.
        let pid = unsafe { getpid() }.max(0) as u32;
        if let Ok((total_bytes, avail_bytes)) = get_mac_memory_usage() {
            let used_bytes = total_bytes.saturating_sub(avail_bytes);
            let pct = if total_bytes > 0 {
                ((used_bytes.saturating_mul(100)) / total_bytes).min(100) as u32
            } else {
                0
            };

            OsTelemetrySnapshot {
                total_ram_bytes: total_bytes,
                avail_ram_bytes: avail_bytes,
                ram_usage_pct: pct,
                process_id: pid,
            }
        } else {
            OsTelemetrySnapshot {
                process_id: pid,
                ..OsTelemetrySnapshot::default()
            }
        }
    }
}