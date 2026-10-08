//! b017 - BOLT layer-1 token templates and the off-chain scanner, transcribed function for function from the
//! TypeScript reference (BOLT-Association/b017) and held to it by the shared vectors in `../vectors`.
//!
//! The module layout follows the reference's files (and the Go port's): `script`/`tx`/`sighash`/`merklepath`/
//! `beefsdk`/`spend`/`txbuild` reproduce the parts of @bsv/sdk 2.8.11 b017 depends on; the rest is b017.

pub mod error;
pub mod script;
pub mod tx;
pub mod sighash;
pub mod merklepath;
pub mod beefsdk;
pub mod spend;
pub mod suffixes_gen;
pub mod boltlib;
pub mod fingerprints;
pub mod beef;
pub mod pay2proof;
pub mod singleancestor;
pub mod singlespend;
pub mod nfttemplates;
pub mod verifyevents;
pub mod txbuild;
pub mod simplemulti;
pub mod multiboltlib;
pub mod multibolt;

pub use error::{Error, Result};
pub use script::{Chunk, Script};
pub use tx::{Input, Output, Transaction, TxRef};
