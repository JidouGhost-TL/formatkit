//! Platform-neutral binary patch formats with explicit application policy.
//!
//! # Modules
//! - [`ips`]: International Patching System (IPS / IPS32) parsing, creation, and policy-controlled application.
//! - [`bps`]: Beat Patching System (`BPS1`) parsing, encoding, CRC-32 verification, and application.
//! - [`ups`]: Universal Patching System (`UPS1`) XOR-delta parsing, encoding, and application.
//! - [`vli`]: Bijective base-128 variable-length integer encoding and decoding shared by BPS and UPS.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
/// Beat Patching System (`BPS1`) binary patch parser, applier, and encoder.
pub mod bps;
/// International Patching System (IPS) binary patch parser, creator, and policy-controlled applier.
pub mod ips;
/// Universal Patching System (`UPS1`) XOR-delta patch parser, applier, and encoder.
pub mod ups;
/// Bijective base-128 variable-length integer (VLI) encoder and decoder.
#[doc(alias = "varint")]
#[doc(alias = "leb128")]
pub mod vli;
