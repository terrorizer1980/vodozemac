// Copyright 2021 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    io::{Cursor, Read},
    ops::Deref,
};

use block_modes::BlockModeError;
use hmac::digest::MacError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use super::{
    message::MegolmMessage,
    ratchet::{MegolmRatchetUnpicklingError, Ratchet, RatchetPickle},
    session_key::GenericSessionKey,
    SessionCreationError, SessionKey,
};
use crate::{
    cipher::Cipher,
    types::{Ed25519PublicKey, SignatureError},
    utilities::{base64_decode, base64_encode},
    DecodeError,
};

const SESSION_KEY_EXPORT_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("The signature on the session key was invalid: {0}")]
    Signature(#[from] SignatureError),
    #[error("Failed decrypting Megolm message, invalid MAC: {0}")]
    InvalidMAC(#[from] MacError),
    #[error("Failed decrypting Megolm message, invalid ciphertext: {0}")]
    InvalidCiphertext(#[from] BlockModeError),
    #[error(
        "The message was encrypted using an unknown message index, \
        first known index {0}, index of the message {1}"
    )]
    UnknownMessageIndex(u32, u32),
    #[error("The message couldn't be decoded: {0}")]
    DecodeError(#[from] DecodeError),
}

#[derive(Deserialize)]
#[serde(try_from = "InboundGroupSessionPickle")]
pub struct InboundGroupSession {
    initial_ratchet: Ratchet,
    latest_ratchet: Ratchet,
    signing_key: Ed25519PublicKey,
    #[allow(dead_code)]
    signing_key_verified: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedMessage {
    pub plaintext: String,
    pub message_index: u32,
}

#[derive(Zeroize)]
pub struct ExportedSessionKey(pub String);

impl ExportedSessionKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl GenericSessionKey for ExportedSessionKey {
    const SESSION_KEY_VERSION: u8 = SESSION_KEY_EXPORT_VERSION;

    fn as_str(&self) -> &str {
        self.as_str()
    }
}

impl Drop for ExportedSessionKey {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl InboundGroupSession {
    pub fn new(session_key: &SessionKey) -> Result<Self, SessionCreationError> {
        Self::new_helper(session_key, true)
    }

    pub fn import(exported_session_key: &ExportedSessionKey) -> Result<Self, SessionCreationError> {
        Self::new_helper(exported_session_key, false)
    }

    fn new_helper(
        session_key: &impl GenericSessionKey,
        verify_signature: bool,
    ) -> Result<Self, SessionCreationError> {
        let (initial_ratchet, signing_key) = session_key.parse(verify_signature)?;
        let latest_ratchet = initial_ratchet.clone();

        Ok(Self {
            initial_ratchet,
            latest_ratchet,
            signing_key,
            signing_key_verified: verify_signature,
        })
    }

    pub fn session_id(&self) -> String {
        base64_encode(self.signing_key.as_bytes())
    }

    pub fn first_known_index(&self) -> u32 {
        self.initial_ratchet.index()
    }

    fn find_ratchet(&mut self, message_index: u32) -> Option<&Ratchet> {
        if self.initial_ratchet.index() == message_index {
            Some(&self.initial_ratchet)
        } else if self.latest_ratchet.index() == message_index {
            Some(&self.latest_ratchet)
        } else if self.latest_ratchet.index() < message_index {
            self.latest_ratchet.advance_to(message_index);
            Some(&self.latest_ratchet)
        } else if self.initial_ratchet.index() < message_index {
            self.latest_ratchet = self.initial_ratchet.clone();
            self.latest_ratchet.advance_to(message_index);
            Some(&self.latest_ratchet)
        } else {
            None
        }
    }

    pub fn decrypt(&mut self, ciphertext: &str) -> Result<DecryptedMessage, DecryptionError> {
        let message = MegolmMessage::try_from(ciphertext)?;

        message.verify_signature(&self.signing_key)?;

        if let Some(ratchet) = self.find_ratchet(message.message_index) {
            let cipher = Cipher::new_megolm(ratchet.as_bytes());

            cipher.verify_mac(message.source.bytes_for_mac(), &message.mac)?;
            let plaintext =
                String::from_utf8_lossy(&cipher.decrypt(&message.ciphertext)?).to_string();

            Ok(DecryptedMessage { plaintext, message_index: message.message_index })
        } else {
            Err(DecryptionError::UnknownMessageIndex(
                self.initial_ratchet.index(),
                message.message_index,
            ))
        }
    }

    pub fn export_at(&mut self, index: u32) -> Option<ExportedSessionKey> {
        let signing_key = self.signing_key;

        if let Some(ratchet) = self.find_ratchet(index) {
            let index = ratchet.index().to_be_bytes();

            let mut export: Vec<u8> = [
                [SESSION_KEY_EXPORT_VERSION].as_ref(),
                index.as_ref(),
                ratchet.as_bytes(),
                signing_key.as_bytes(),
            ]
            .concat();

            let result = base64_encode(&export);
            export.zeroize();

            Some(ExportedSessionKey(result))
        } else {
            None
        }
    }

    pub fn pickle_to_json_string(&self) -> InboundGroupSessionPickledJSON {
        let pickle: InboundGroupSessionPickle = self.pickle();
        InboundGroupSessionPickledJSON(
            serde_json::to_string_pretty(&pickle)
                .expect("Inbound group session serialization failed."),
        )
    }

    pub fn unpickle_from_json_str(input: &str) -> Result<Self, InboundGroupSessionUnpicklingError> {
        let pickle: InboundGroupSessionPickle = serde_json::from_str(input)?;
        pickle.try_into()
    }

    pub fn pickle(&self) -> InboundGroupSessionPickle {
        InboundGroupSessionPickle {
            initial_ratchet: self.initial_ratchet.clone().into(),
            latest_ratchet: self.latest_ratchet.clone().into(),
            signing_key: self.signing_key,
            signing_key_verified: self.signing_key_verified,
        }
    }

    pub fn from_libolm_pickle(
        pickle: &str,
        pickle_key: &str,
    ) -> Result<Self, crate::LibolmUnpickleError> {
        use crate::utilities::{read_bool, read_u32};

        const PICKLE_VERSION: u32 = 2;

        let cipher = Cipher::new_pickle(pickle_key.as_ref());

        let decoded = base64_decode(pickle)?;
        let decrypted = cipher.decrypt_pickle(&decoded)?;

        let mut cursor = Cursor::new(decrypted);
        let version = read_u32(&mut cursor)?;

        if version != 2 {
            Err(crate::LibolmUnpickleError::Version(PICKLE_VERSION, version))
        } else {
            let mut ratchet = [0u8; Ratchet::RATCHET_LENGTH];

            cursor.read_exact(&mut ratchet)?;
            let counter = read_u32(&mut cursor)?;
            let initial_ratchet = Ratchet::from_bytes(ratchet, counter);

            cursor.read_exact(&mut ratchet)?;
            let counter = read_u32(&mut cursor)?;
            let latest_ratchet = Ratchet::from_bytes(ratchet, counter);

            let mut signing_key = [0u8; Ed25519PublicKey::LENGTH];
            cursor.read_exact(&mut signing_key)?;
            let signing_key = Ed25519PublicKey::from_bytes(&signing_key)?;

            let signing_key_verified = read_bool(&mut cursor)?;

            Ok(Self { initial_ratchet, latest_ratchet, signing_key, signing_key_verified })
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct InboundGroupSessionPickle {
    initial_ratchet: RatchetPickle,
    latest_ratchet: RatchetPickle,
    signing_key: Ed25519PublicKey,
    #[allow(dead_code)]
    signing_key_verified: bool,
}

impl InboundGroupSessionPickle {
    pub fn unpickle(self) -> Result<InboundGroupSession, InboundGroupSessionUnpicklingError> {
        self.try_into()
    }
}

impl TryFrom<InboundGroupSessionPickle> for InboundGroupSession {
    type Error = InboundGroupSessionUnpicklingError;

    fn try_from(pickle: InboundGroupSessionPickle) -> Result<Self, Self::Error> {
        Ok(Self {
            initial_ratchet: pickle
                .initial_ratchet
                .try_into()
                .map_err(InboundGroupSessionUnpicklingError::InvalidInitialRatchet)?,
            latest_ratchet: pickle
                .latest_ratchet
                .try_into()
                .map_err(InboundGroupSessionUnpicklingError::InvalidLatestRatchet)?,
            signing_key: pickle.signing_key,
            signing_key_verified: pickle.signing_key_verified,
        })
    }
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct InboundGroupSessionPickledJSON(String);

impl InboundGroupSessionPickledJSON {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn unpickle(self) -> Result<InboundGroupSession, InboundGroupSessionUnpicklingError> {
        let pickle: InboundGroupSessionPickle = serde_json::from_str(&self.0)?;
        pickle.unpickle()
    }
}

impl AsRef<str> for InboundGroupSessionPickledJSON {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for InboundGroupSessionPickledJSON {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

#[derive(Error, Debug)]
pub enum InboundGroupSessionUnpicklingError {
    #[error("Invalid initial ratchet")]
    InvalidInitialRatchet(MegolmRatchetUnpicklingError),
    #[error("Invalid latest ratchet")]
    InvalidLatestRatchet(MegolmRatchetUnpicklingError),
    #[error("Invalid public signing key: {0}")]
    InvalidSigningPublicKey(SignatureError),
    #[error("Pickle format corrupted: {0}")]
    CorruptedPickle(#[from] serde_json::error::Error),
}
