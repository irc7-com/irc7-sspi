//! Main entry point and orchestration for MSN Chat SSPI Security Providers.
//! Re-exports all providers, handles, and structures in a flat public API to maintain backward compatibility.

pub mod types;
pub mod default;
pub mod passport;
pub mod gatekeeper;
pub mod ntlm;
pub mod gatekeeper_passport;
pub mod ntlm_passport;

// Flat public re-exports so that external dependencies can still import
// from the root: `use ircx_sspi::{SecurityProvider, CredHandle, ...}`
pub use types::{SspiError, CredHandle, CtxtHandle, SecBufferType, SecBuffer, SecurityProvider, CombinedContext};
pub use default::DefaultSecurityProvider;
pub use passport::{PassportSecurityProvider, PassportSession};
pub use gatekeeper::{GateKeeperSecurityProvider, GateKeeperSession, GkStateFlags};
pub use ntlm::NtlmSecurityProvider;
pub use gatekeeper_passport::GateKeeperPassportSecurityProvider;
pub use ntlm_passport::NtlmPassportSecurityProvider;

pub mod dll;
