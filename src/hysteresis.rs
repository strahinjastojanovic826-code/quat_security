use crate::state::QuadState;
use crate::policy::SecurityPolicy;

pub struct HysteresisEvaluator {
    // High thresholds for escalating state (00 -> 01 -> 10 -> 11)
    pub elevated_high: u32, // e.g. 75%
    pub critical_high: u32, // e.g. 90%
    pub lockdown_high: u32, // e.g. 98%

    // Low thresholds for de-escalating state (11 -> 10 -> 01 -> 00)
    pub elevated_low: u32,  // e.g. 65%
    pub critical_low: u32,  // e.g. 80%
    pub lockdown_low: u32,  // e.g. 92%
}

impl Default for HysteresisEvaluator {
    fn default() -> Self {
        Self {
            elevated_high: 75,
            elevated_low: 65,
            critical_high: 90,
            critical_low: 80,
            lockdown_high: 98,
            lockdown_low: 92,
        }
    }
}

impl HysteresisEvaluator {
    /// Evaluates target state considering multivariate threat score and current state hysteresis
    pub fn evaluate_next_state(&self, current_state: QuadState, threat_score: u32) -> QuadState {
        match current_state {
            // State 00: Nominal
            QuadState::Nominal => {
                if threat_score >= self.lockdown_high {
                    QuadState::Lockdown // 11
                } else if threat_score >= self.critical_high {
                    QuadState::Critical // 10
                } else if threat_score >= self.elevated_high {
                    QuadState::Elevated // 01
                } else {
                    QuadState::Nominal // 00
                }
            }
            // State 01: Elevated
            QuadState::Elevated => {
                if threat_score >= self.lockdown_high {
                    QuadState::Lockdown // 11
                } else if threat_score >= self.critical_high {
                    QuadState::Critical // 10
                } else if threat_score < self.elevated_low {
                    QuadState::Nominal // 00 (De-escalate)
                } else {
                    QuadState::Elevated // 01 (Maintain)
                }
            }
            // State 10: Critical
            QuadState::Critical => {
                if threat_score >= self.lockdown_high {
                    QuadState::Lockdown // 11
                } else if threat_score < self.critical_low {
                    QuadState::Elevated // 01 (De-escalate)
                } else {
                    QuadState::Critical // 10 (Maintain)
                }
            }
            // State 11: Lockdown
            QuadState::Lockdown => {
                if threat_score < self.lockdown_low {
                    QuadState::Critical // 10 (De-escalate)
                } else {
                    QuadState::Lockdown // 11 (Maintain)
                }
            }
        }
    }
    
    pub fn from_policy(policy: &SecurityPolicy) -> Self {
        let elevated_high = policy.ram_threshold_elevated.min(100);
        let critical_high = policy
            .ram_threshold_critical
            .max(policy.cpu_threshold_critical)
            .min(100);
        let lockdown_high = if policy.auto_lockdown_on_breach {
            98
        } else {
            100
        };

        Self {
            elevated_high,
            critical_high,
            lockdown_high,
            elevated_low: elevated_high.saturating_sub(10),
            critical_low: critical_high.saturating_sub(10),
            lockdown_low: lockdown_high.saturating_sub(6),
        }
    }
}