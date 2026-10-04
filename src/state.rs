#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QuadState {
    Nominal = 0,   // 0b00 - Normalan rad
    Elevated = 1,  // 0b01 - Upozorenje / Povećani resursi
    Critical = 2,  // 0b10 - Sumnjive aktivnosti
    Lockdown = 3,  // 0b11 - Mitigacija / Gašenje procesa
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
    None = 0,
    MemoryThresholdExceeded = 1,
    ManualOverride = 2,
    ProcessTerminationFailure = 3,
}

impl QuadReason {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => QuadReason::None,
            0b01 => QuadReason::MemoryThresholdExceeded,
            0b10 => QuadReason::ManualOverride,
            _ => QuadReason::ProcessTerminationFailure,
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