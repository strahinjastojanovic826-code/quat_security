#[repr(i32)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QuadError {
    Ok = 0,
    NullPointer = -1,
    AccessDenied = -2,
    InvalidPid = -3,
    SelfTerminationBlocked = -4,
    LockError = -5,
    UnknownError = -99,
}