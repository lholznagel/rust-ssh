#![deny(
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unstable_features,
    unused_import_braces,
    unused_qualifications,
    warnings
)]

mod algorithms;
mod kex;
mod kexdh;
mod key;
mod version;

mod misc {
    mod builder;
    mod parser;

    pub use self::builder::Builder;
    pub use self::parser::Parser;
}

pub mod server;
