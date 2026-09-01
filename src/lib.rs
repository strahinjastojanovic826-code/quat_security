/*
 * QUAD-GUARD SECURITY TELEMETRY CORE
 * 4-State Biological Model | Zero-Dependency
 * Cross-Platform: Windows, Linux & C-ABI Support
 */


#[cfg(target_os = "linux")]
use std::fs;

// =================================================================
// 1. WINDOWS NATIVE API (WIN_API MODUL)
// =================================================================

#[cfg(target_os = "windows")]
pub mod win_api {
    #[repr(C)]
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

    unsafe extern "system" {
        pub fn GlobalMemoryStatusEx(lp_buffer: *mut MEMORYSTATUSEX) -> i32;
        pub fn OpenProcess(dw_desired_access: u32, b_inherit_handle: i32, dw_process_id: u32) -> *mut usize;
        pub fn TerminateProcess(h_process: *mut usize, u_exit_code: u32) -> i32;
        pub fn CloseHandle(h_object: *mut usize) -> i32;
    }
}

// =================================================================
// 2. 4-STANJA MODEL (QUAD-STATES)
// =================================================================

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum QuadState {
    Nominal = 0,   // Normalan rad
    Elevated = 1,  // Upozorenje / Povećani resursi
    Critical = 2,  // Sumnjive aktivnosti
    Lockdown = 3,  // Mitigacija / Gašenje procesa
}

pub struct QuadGuard {
    pub current_state: QuadState,
}

impl QuadGuard {
    pub fn new() -> Self {
        QuadGuard {
            current_state: QuadState::Nominal,
        }
    }

    pub fn analyze(&mut self) -> QuadState {
        println!("[QuadGuard Core] Pokretanje telemetrije...");

        #[cfg(target_os = "windows")]
        {
            let mut status = win_api::MEMORYSTATUSEX {
                dw_length: std::mem::size_of::<win_api::MEMORYSTATUSEX>() as u32,
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
                if win_api::GlobalMemoryStatusEx(&mut status) != 0 {
                    println!("[WinEngine] RAM Opterećenje: {}%", status.dw_memory_load);
                    if status.dw_memory_load > 80 {
                        self.current_state = QuadState::Elevated;
                    } else {
                        self.current_state = QuadState::Nominal;
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(_mem_info) = fs::read_to_string("/proc/meminfo") {
                println!("[LinuxEngine] Uspešno pročitan /proc/meminfo");
            }
            self.current_state = QuadState::Nominal;
        }

        self.current_state
    }
}

// =================================================================
// 3. C-ABI IZVOZ (Podrška za C i C++ na Linux-u i Windows-u)
// =================================================================

#[unsafe(no_mangle)]
pub extern "C" fn quad_guard_new() -> *mut QuadGuard {
    Box::into_raw(Box::new(QuadGuard::new()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_free(ptr: *mut QuadGuard) { unsafe {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_analyze(ptr: *mut QuadGuard) -> QuadState { unsafe {
    if ptr.is_null() {
        return QuadState::Nominal;
    }
    let guard = &mut *ptr;
    guard.analyze()
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn quad_guard_terminate(ptr: *mut QuadGuard, pid: u32) -> i32 { unsafe {
    if ptr.is_null() {
        return 0;
    }
    let guard = &mut *ptr;
    guard.current_state = QuadState::Lockdown;

    #[cfg(target_os = "windows")]
    {
        let handle = win_api::OpenProcess(0x0001, 0, pid);
        if !handle.is_null() {
            let res = win_api::TerminateProcess(handle, 1);
            win_api::CloseHandle(handle);
            return res;
        }
    }

    #[cfg(target_os = "linux")]
    {
        let exe_link = format!("/proc/{}/exe", pid);
        if fs::metadata(exe_link).is_ok() {
            return 1;
        }
    }

    0
}}

// =================================================================
// 4. MAIN GLAVNI POKRETAČ (Za direktno testiranje u Rustu)
// =================================================================

pub fn main() {
    println!("=== QUAD-GUARD START ===");
    let mut guard = QuadGuard::new();
    let state = guard.analyze();
    println!("Trenutno stanje: {:?}", state);
    println!("=== QUAD-GUARD END ===");
}