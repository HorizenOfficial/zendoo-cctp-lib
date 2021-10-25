//! # Utils
//!
//! `utils` contains some macros to handle the debug print messages.

// Disable warnings
#[allow(unused_macros)]

/// Prints a string to standard output only if `debug_assertions` is set
/// (i.e. only if the compilation is performed without optimization).
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! printdbg {
    ($( $args:expr ),*) => { print!( $( $args ),* ); }
}

/// Prints a line to standard output only if `debug_assertions` is set
/// (i.e. only if the compilation is performed without optimization).
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! printlndbg {
    ($( $args:expr ),*) => { println!( $( $args ),* ); }
}

/// Prints a string to standard output only if `debug_assertions` is set
/// (i.e. only if the compilation is performed without optimization).
#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! printdbg {
    ($( $args:expr ),*) => {
        ()
    };
}

/// Prints a line to standard output only if `debug_assertions` is set
/// (i.e. only if the compilation is performed without optimization).
#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! printlndbg {
    ($( $args:expr ),*) => {
        ()
    };
}
