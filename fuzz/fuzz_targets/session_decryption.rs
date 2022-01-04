#![no_main]
use libfuzzer_sys::fuzz_target;
use vodozemac::olm::{Account, OlmMessage};

fuzz_target!(|message: OlmMessage| {
    let alice = Account::new();
    let mut bob = Account::new();
    bob.generate_one_time_keys(1);

    let mut session = alice.create_outbound_session(
        *bob.curve25519_key(),
        *bob.one_time_keys().values().next().unwrap(),
    );

    if session.decrypt(&message).is_ok() {
        panic!("Decrypted a forged message");
    }
});
