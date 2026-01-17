// Debug logging utilities

// set to false in production
pub const DEBUG_ENABLED: bool = true;

// debug logging macro that can be disabled in prod
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if $crate::debug::DEBUG_ENABLED {
            eprintln!("[DEBUG] {}", format!($($arg)*));
        }
    };
}
