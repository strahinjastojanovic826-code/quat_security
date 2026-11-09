#[derive(Debug, Clone, Copy)]
pub struct SystemMetrics {
    pub ram_usage_pct: u32,
    pub cpu_usage_pct: u32,
    pub io_wait_pct: u32,
    pub network_load_pct: u32,
    pub gpu_temp_celsius: u32,
}

impl SystemMetrics {
    // Svi parametri moraju biti navedeni u zagradama funkcije new
    pub fn new(
        ram_usage_pct: u32, 
        cpu_usage_pct: u32, 
        io_wait_pct: u32,
        network_load_pct: u32,
        gpu_temp_celsius: u32,
    ) -> Self {
        Self {
            ram_usage_pct,
            cpu_usage_pct,
            io_wait_pct,
            network_load_pct,
            gpu_temp_celsius,
        }
    }

    /// Calculates a weighted multivariate threat index (0 - 100)
    pub fn calculate_threat_score(&self) -> u32 {
        let ram_comp = (self.ram_usage_pct as f32) * 0.30;
        let cpu_comp = (self.cpu_usage_pct as f32) * 0.25;
        let io_comp = (self.io_wait_pct as f32) * 0.10;
        let net_comp = (self.network_load_pct as f32) * 0.15;
        
        // Normalizacija temperature GPU-a (pretpostavka: kritično preko 85°C / 100°C max)
        let gpu_comp = ((self.gpu_temp_celsius.min(100) as f32) / 100.0) * 20.0;

        (ram_comp + cpu_comp + io_comp + net_comp + gpu_comp).round() as u32
    }
}