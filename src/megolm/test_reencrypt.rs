use crate::{megolm::GroupSession, utilities::base64_decode};

use super::{message::MegolmMessage, InboundGroupSession};

#[test]
fn reencrypt() {
    let mut session = GroupSession::new();
    let session_key = session.session_key();

    let plaintext = "foobar";

    let ciphertext = session.encrypt(plaintext);

    let mut inbound_session = InboundGroupSession::new(&session_key).expect("f");
    let mut fake_session = GroupSession::from_inbound_session(&inbound_session);
    assert_eq!(inbound_session.decrypt(&ciphertext).expect("f").plaintext, plaintext);

    let second_ciphertext = fake_session.encrypt(plaintext);

    let ciphertext_bytes = base64_decode(&ciphertext).expect("f");
    let (_, decoded_megolm) = MegolmMessage::decode(ciphertext_bytes).expect("f");

    let second_ciphertext_bytes = base64_decode(&second_ciphertext).expect("f");
    let (_, second_decoded_megolm) = MegolmMessage::decode(second_ciphertext_bytes).expect("f");

    assert_eq!(decoded_megolm.ciphertext, second_decoded_megolm.ciphertext);
    assert_eq!(decoded_megolm.message_index, second_decoded_megolm.message_index);
    assert_eq!(decoded_megolm.mac, second_decoded_megolm.mac);
    // assert_eq!(decoded_megolm.signature.0, second_decoded_megolm.signature.0);
}
