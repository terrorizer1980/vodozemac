use std::io::{Cursor, Read};

use thiserror::Error;
use zeroize::Zeroize;

use super::{ratchet::Ratchet, SESSION_KEY_VERSION};
use crate::{
    types::{Ed25519Signature, SignatureError},
    utilities::base64_decode,
    Ed25519PublicKey,
};

#[derive(Debug, Error)]
pub enum SessionCreationError {
    #[error("The session had a invalid version, expected {0}, got {1}")]
    Version(u8, u8),
    #[error("The session key was too short {0}")]
    Read(#[from] std::io::Error),
    #[error("The session key wasn't valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("The signature on the session key was invalid: {0}")]
    Signature(#[from] SignatureError),
}

pub trait GenericSessionKey {
    const SESSION_KEY_VERSION: u8;

    fn as_str(&self) -> &str;

    fn parse(
        &self,
        verify_signature: bool,
    ) -> Result<(Ratchet, Ed25519PublicKey), SessionCreationError> {
        let decoded = base64_decode(self.as_str())?;
        let mut cursor = Cursor::new(decoded);

        let mut version = [0u8; 1];
        let mut index = [0u8; 4];
        let mut ratchet = [0u8; 128];
        let mut public_key = [0u8; Ed25519PublicKey::LENGTH];

        cursor.read_exact(&mut version)?;

        let expected_version = Self::SESSION_KEY_VERSION;

        if version[0] != expected_version {
            Err(SessionCreationError::Version(SESSION_KEY_VERSION, version[0]))
        } else {
            cursor.read_exact(&mut index)?;
            cursor.read_exact(&mut ratchet)?;
            cursor.read_exact(&mut public_key)?;

            let signing_key = Ed25519PublicKey::from_bytes(&public_key)?;

            if verify_signature {
                let mut signature = [0u8; Ed25519Signature::LENGTH];

                cursor.read_exact(&mut signature)?;
                let signature = Ed25519Signature::from_bytes(&signature)?;

                let decoded = cursor.into_inner();

                signing_key.verify(&decoded[..decoded.len() - 64], &signature)?;
            }

            let index = u32::from_be_bytes(index);
            let ratchet = Ratchet::from_bytes(ratchet, index);

            Ok((ratchet, signing_key))
        }
    }
}

#[derive(Zeroize)]
pub struct SessionKey(pub String);

impl SessionKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl GenericSessionKey for SessionKey {
    const SESSION_KEY_VERSION: u8 = SESSION_KEY_VERSION;

    fn as_str(&self) -> &str {
        self.as_str()
    }
}
