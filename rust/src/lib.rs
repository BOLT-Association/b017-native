//! b017 - BOLT layer-1 token templates and the off-chain scanner, transcribed function for function from the
//! TypeScript reference (BOLT-Association/b017) and held to it by the shared vectors in `../vectors`.
//!
//! The module layout follows the reference's files (and the Go port's): `script`/`tx`/`sighash`/`merklepath`/
//! `beefsdk`/`spend`/`txbuild` reproduce the parts of @bsv/sdk 2.8.11 b017 depends on; the rest is b017.

pub mod beef;
pub mod beefsdk;
pub mod boltlib;
pub mod error;
pub mod fingerprints;
pub mod merklepath;
pub mod multibolt;
pub mod multiboltlib;
pub mod nfttemplates;
pub mod pay2proof;
pub mod script;
pub mod sighash;
pub mod simplemulti;
pub mod singleancestor;
pub mod singlespend;
pub mod spend;
pub mod suffixes_gen;
pub mod tx;
pub mod txbuild;
pub mod verifyevents;

pub use error::{Error, Result};
pub use script::{Chunk, Script};
pub use tx::{Input, Output, Transaction, TxRef};
