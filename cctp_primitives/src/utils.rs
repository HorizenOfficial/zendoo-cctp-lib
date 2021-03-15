// Disable warnings
#[allow(unused_macros)]

// Debug version
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! printdbg {
    ($( $args:expr ),*) => { print!( $( $args ),* ); }
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! printlndbg {
    ($( $args:expr ),*) => { println!( $( $args ),* ); }
}

// Non-debug version
#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! printdbg {
    ($( $args:expr ),*) => {()}
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! printlndbg {
    ($( $args:expr ),*) => {()}
}