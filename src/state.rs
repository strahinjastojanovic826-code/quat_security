#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QuadState {
    Nominal = 0,   // 0b00 - Normalan rad
    Elevated = 1,  // 0b01 - Upozorenje / Povećani resursi
    Critical = 2,  // 0b10 - Sumnjive aktivnosti
    Lockdown = 3,  // 0b11 - Mitigacija / Gašenje procesa
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuadAction {
    LogOnly = 0,
    CallbackOnly = 1,
    TerminateProcess = 2,
}

impl QuadState {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => QuadState::Nominal,
            0b01 => QuadState::Elevated,
            0b10 => QuadState::Critical,
            _ => QuadState::Lockdown,
        }
    }

    pub fn to_bits(self) -> u8 {
        self as u8
    }

    pub fn from_byte_shift(byte: u8, pair_index: u8) -> Self {
        let shift = (pair_index & 0b11) * 2;
        let bits = (byte >> shift) & 0b11;
        Self::from_bits(bits)
    }
}

impl From<u8> for QuadState {
    fn from(val: u8) -> Self {
        Self::from_bits(val)
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QuadReason {
    None = 0,               // 0b00 - No transition / nominal
    ResourceThreshold = 1,  // 0b01 - Elevated RAM / CPU / IO / telemetry threshold
    ThreatEscalation = 2,   // 0b10 - Critical score / sustained high threat
    LockdownPolicy = 3,     // 0b11 - Lockdown triggered by policy / watchdog
}

impl QuadReason {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
             0b00 => QuadReason::None,
             0b01 => QuadReason::ResourceThreshold,
             0b10 => QuadReason::ThreatEscalation,
            _ => QuadReason::LockdownPolicy,
        }
    }
}

impl From<u8> for QuadReason {
    fn from(val: u8) -> Self {
        Self::from_bits(val)
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct StateEvent {
    pub previous_state: QuadState,
    pub new_state: QuadState,
    pub timestamp_sec: u64,
    pub reason: QuadReason,
}

impl StateEvent {
    pub fn new(
        previous: QuadState,
        new: QuadState,
        reason: QuadReason,
        timestamp: u64,
    ) -> Self {
        Self {
            previous_state: previous,
            new_state: new,
            timestamp_sec: timestamp,
            reason,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct QuadPack4(pub u8);

impl QuadPack4 {
    pub const fn new() -> Self {
        Self(0)
    }

    /// Lane index 0..=3 (2 bits per lane: 00, 01, 10, 11)
    pub fn get(self, lane: u8) -> QuadState {
        let shift = (lane & 0b11) * 2;
        let bits = (self.0 >> shift) & 0b11;
        QuadState::from_bits(bits)
    }

    pub fn set(&mut self, lane: u8, state: QuadState) {
        let shift = (lane & 0b11) * 2;
        let mask = !(0b11_u8 << shift);
        let val = (state.to_bits() & 0b11) << shift;
        self.0 = (self.0 & mask) | val;
    }
}