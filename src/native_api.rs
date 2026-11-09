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

    extern "system" {
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