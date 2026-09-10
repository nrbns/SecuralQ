//! Local key material. Private keys never leave the endpoint.
//! Phase 1 uses enrollment HMAC key from admin token; Ed25519 device keys later.

pub struct KeyPairStub;

impl KeyPairStub {
    pub fn generate() -> Self {
        Self
    }
}
