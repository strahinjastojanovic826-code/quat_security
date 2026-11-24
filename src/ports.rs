use crate::state::{QuadAction, StateEvent};

#[derive(Debug, Clone, Copy)]
pub struct TelemetrySample {
    pub ram_usage_pct: u32,
    pub cpu_usage_pct: u32,
    pub io_wait_pct: u32,
    pub network_load_pct: u32,
    pub gpu_temp_celsius: u32,
}

pub trait TelemetryProvider: Send + Sync {
    fn sample(&self) -> TelemetrySample;
}

pub trait ActionDispatcher: Send + Sync {
    fn dispatch(
        &self,
        action: QuadAction,
        event: &StateEvent,
        threat_score: u32,
    );
}