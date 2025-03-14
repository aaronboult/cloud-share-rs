// Macro that conditionally calls println! based on Option<bool>
#[macro_export]
macro_rules! println_verbose {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose {
            println!($($arg)*);
        }
    };
}