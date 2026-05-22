//! Main entry point and orchestration for MSN Chat SSPI Security Providers.
//! Re-exports all providers, handles, and structures in a flat public API to maintain backward compatibility.

pub mod types;
pub mod default;
pub mod gatekeeper;
pub mod ntlm;
pub mod vault;

pub mod internal {
    pub mod sam {
        use zeroize::Zeroize;

        #[derive(Zeroize)]
        #[zeroize(drop)]
        pub struct SamPackage {
            pub username: String,
            pub nt_hash: [u8; 16],
        }

        impl SamPackage {
            pub fn new(username: String, nt_hash: [u8; 16]) -> Self {
                Self { username, nt_hash }
            }
        }
    }
}

// Flat public re-exports so that external dependencies can still import
// from the root: `use ircx_sspi::{SecurityProvider, CredHandle, ...}`
pub use types::{SspiError, CredHandle, CtxtHandle, SecBufferType, SecBuffer, SecurityProvider};
pub use default::DefaultSecurityProvider;
pub use gatekeeper::{GateKeeperSecurityProvider, GateKeeperSession, GkStateFlags};
pub use ntlm::NtlmSecurityProvider;

pub mod dll;

