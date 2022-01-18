// Copyright 2021 Damir Jelić, Denis Kasak
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

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{ratchet::RatchetPublicKey, DecryptionError};
use crate::{
    cipher::Cipher,
    olm::messages::{DecodedMessage, EncodedMessage},
};

pub struct MessageKey {
    key: [u8; 32],
    ratchet_key: RatchetPublicKey,
    index: u64,
}

impl Drop for MessageKey {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct RemoteMessageKey {
    pub key: [u8; 32],
    pub index: u64,
}

impl Drop for RemoteMessageKey {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

impl MessageKey {
    pub fn new(key: [u8; 32], ratchet_key: RatchetPublicKey, index: u64) -> Self {
        Self { key, ratchet_key, index }
    }

    pub fn encrypt(self, plaintext: &[u8]) -> EncodedMessage {
        let cipher = Cipher::new(&self.key);

        let ciphertext = cipher.encrypt(plaintext);

        let mut message = EncodedMessage::new(self.ratchet_key.as_ref(), self.index, ciphertext);

        let mac = cipher.mac(message.as_payload_bytes());
        message.append_mac(mac);

        message
    }

    /// Get the message key's key.
    pub fn key(&self) -> [u8; 32] {
        self.key
    }

    /// Get a reference to the message key's ratchet key.
    pub fn ratchet_key(&self) -> &RatchetPublicKey {
        &self.ratchet_key
    }

    /// Get the message key's index.
    pub fn index(&self) -> u64 {
        self.index
    }
}

impl RemoteMessageKey {
    pub fn new(key: [u8; 32], index: u64) -> Self {
        Self { key, index }
    }

    pub fn chain_index(&self) -> u64 {
        self.index
    }

    pub fn decrypt(&self, message: &DecodedMessage) -> Result<Vec<u8>, DecryptionError> {
        let cipher = Cipher::new(&self.key);

        cipher.verify_mac(message.source.as_payload_bytes(), &message.mac)?;
        Ok(cipher.decrypt(&message.ciphertext)?)
    }
}
