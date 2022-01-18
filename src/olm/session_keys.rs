// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use crate::Curve25519PublicKey;

/// The set of keys that were used to establish the Olm Session,
#[derive(Serialize, Deserialize, Clone)]
pub struct SessionKeys {
    pub identity_key: Curve25519PublicKey,
    pub base_key: Curve25519PublicKey,
    pub one_time_key: Curve25519PublicKey,
}

pub(crate) type SessionKeysPickle = SessionKeys;
