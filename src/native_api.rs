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