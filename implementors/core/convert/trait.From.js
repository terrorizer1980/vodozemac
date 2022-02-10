(function() {var implementors = {};
implementors["vodozemac"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.array.html\">[</a><a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a><a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.array.html\">; 32]</a>&gt; for <a class=\"struct\" href=\"vodozemac/struct.Curve25519PublicKey.html\" title=\"struct vodozemac::Curve25519PublicKey\">Curve25519PublicKey</a>","synthetic":false,"types":["vodozemac::types::curve25519::Curve25519PublicKey"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;'a <a class=\"struct\" href=\"https://docs.rs/x25519-dalek/1.2.0/x25519_dalek/x25519/struct.StaticSecret.html\" title=\"struct x25519_dalek::x25519::StaticSecret\">StaticSecret</a>&gt; for <a class=\"struct\" href=\"vodozemac/struct.Curve25519PublicKey.html\" title=\"struct vodozemac::Curve25519PublicKey\">Curve25519PublicKey</a>","synthetic":false,"types":["vodozemac::types::curve25519::Curve25519PublicKey"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;'a <a class=\"struct\" href=\"https://docs.rs/x25519-dalek/1.2.0/x25519_dalek/x25519/struct.EphemeralSecret.html\" title=\"struct x25519_dalek::x25519::EphemeralSecret\">EphemeralSecret</a>&gt; for <a class=\"struct\" href=\"vodozemac/struct.Curve25519PublicKey.html\" title=\"struct vodozemac::Curve25519PublicKey\">Curve25519PublicKey</a>","synthetic":false,"types":["vodozemac::types::curve25519::Curve25519PublicKey"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;'a <a class=\"struct\" href=\"https://docs.rs/x25519-dalek/1.2.0/x25519_dalek/x25519/struct.ReusableSecret.html\" title=\"struct x25519_dalek::x25519::ReusableSecret\">ReusableSecret</a>&gt; for <a class=\"struct\" href=\"vodozemac/struct.Curve25519PublicKey.html\" title=\"struct vodozemac::Curve25519PublicKey\">Curve25519PublicKey</a>","synthetic":false,"types":["vodozemac::types::curve25519::Curve25519PublicKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://docs.rs/base64/0.13.0/base64/decode/enum.DecodeError.html\" title=\"enum base64::decode::DecodeError\">DecodeError</a>&gt; for <a class=\"enum\" href=\"vodozemac/enum.SignatureError.html\" title=\"enum vodozemac::SignatureError\">SignatureError</a>","synthetic":false,"types":["vodozemac::types::ed25519::SignatureError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/signature/1.5.0/signature/error/struct.Error.html\" title=\"struct signature::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"vodozemac/enum.SignatureError.html\" title=\"enum vodozemac::SignatureError\">SignatureError</a>","synthetic":false,"types":["vodozemac::types::ed25519::SignatureError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"vodozemac/struct.KeyId.html\" title=\"struct vodozemac::KeyId\">KeyId</a>&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>","synthetic":false,"types":["alloc::string::String"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://docs.rs/base64/0.13.0/base64/decode/enum.DecodeError.html\" title=\"enum base64::decode::DecodeError\">DecodeError</a>&gt; for <a class=\"enum\" href=\"vodozemac/enum.PublicKeyError.html\" title=\"enum vodozemac::PublicKeyError\">PublicKeyError</a>","synthetic":false,"types":["vodozemac::types::PublicKeyError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"vodozemac/enum.SignatureError.html\" title=\"enum vodozemac::SignatureError\">SignatureError</a>&gt; for <a class=\"enum\" href=\"vodozemac/enum.PublicKeyError.html\" title=\"enum vodozemac::PublicKeyError\">PublicKeyError</a>","synthetic":false,"types":["vodozemac::types::PublicKeyError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/serde_json/1.0.78/serde_json/error/struct.Error.html\" title=\"struct serde_json::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"vodozemac/megolm/enum.GroupSessionUnpicklingError.html\" title=\"enum vodozemac::megolm::GroupSessionUnpicklingError\">GroupSessionUnpicklingError</a>","synthetic":false,"types":["vodozemac::megolm::group_session::GroupSessionUnpicklingError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"vodozemac/megolm/enum.SessionCreationError.html\" title=\"enum vodozemac::megolm::SessionCreationError\">SessionCreationError</a>","synthetic":false,"types":["vodozemac::megolm::inbound_group_session::SessionCreationError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://docs.rs/base64/0.13.0/base64/decode/enum.DecodeError.html\" title=\"enum base64::decode::DecodeError\">DecodeError</a>&gt; for <a class=\"enum\" href=\"vodozemac/megolm/enum.SessionCreationError.html\" title=\"enum vodozemac::megolm::SessionCreationError\">SessionCreationError</a>","synthetic":false,"types":["vodozemac::megolm::inbound_group_session::SessionCreationError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"vodozemac/enum.SignatureError.html\" title=\"enum vodozemac::SignatureError\">SignatureError</a>&gt; for <a class=\"enum\" href=\"vodozemac/megolm/enum.SessionCreationError.html\" title=\"enum vodozemac::megolm::SessionCreationError\">SessionCreationError</a>","synthetic":false,"types":["vodozemac::megolm::inbound_group_session::SessionCreationError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"vodozemac/enum.PublicKeyError.html\" title=\"enum vodozemac::PublicKeyError\">PublicKeyError</a>&gt; for <a class=\"enum\" href=\"vodozemac/megolm/enum.SessionCreationError.html\" title=\"enum vodozemac::megolm::SessionCreationError\">SessionCreationError</a>","synthetic":false,"types":["vodozemac::megolm::inbound_group_session::SessionCreationError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"vodozemac/enum.SignatureError.html\" title=\"enum vodozemac::SignatureError\">SignatureError</a>&gt; for <a class=\"enum\" href=\"vodozemac/megolm/enum.DecryptionError.html\" title=\"enum vodozemac::megolm::DecryptionError\">DecryptionError</a>","synthetic":false,"types":["vodozemac::megolm::inbound_group_session::DecryptionError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/digest/0.10.2/digest/mac/struct.MacError.html\" title=\"struct digest::mac::MacError\">MacError</a>&gt; for <a class=\"enum\" href=\"vodozemac/megolm/enum.DecryptionError.html\" title=\"enum vodozemac::megolm::DecryptionError\">DecryptionError</a>","synthetic":false,"types":["vodozemac::megolm::inbound_group_session::DecryptionError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/block-modes/0.8.1/block_modes/errors/struct.BlockModeError.html\" title=\"struct block_modes::errors::BlockModeError\">BlockModeError</a>&gt; for <a class=\"enum\" href=\"vodozemac/megolm/enum.DecryptionError.html\" title=\"enum vodozemac::megolm::DecryptionError\">DecryptionError</a>","synthetic":false,"types":["vodozemac::megolm::inbound_group_session::DecryptionError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"vodozemac/enum.DecodeError.html\" title=\"enum vodozemac::DecodeError\">DecodeError</a>&gt; for <a class=\"enum\" href=\"vodozemac/megolm/enum.DecryptionError.html\" title=\"enum vodozemac::megolm::DecryptionError\">DecryptionError</a>","synthetic":false,"types":["vodozemac::megolm::inbound_group_session::DecryptionError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;'_ <a class=\"struct\" href=\"vodozemac/megolm/struct.GroupSession.html\" title=\"struct vodozemac::megolm::GroupSession\">GroupSession</a>&gt; for <a class=\"struct\" href=\"vodozemac/megolm/struct.InboundGroupSession.html\" title=\"struct vodozemac::megolm::InboundGroupSession\">InboundGroupSession</a>","synthetic":false,"types":["vodozemac::megolm::inbound_group_session::InboundGroupSession"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/serde_json/1.0.78/serde_json/error/struct.Error.html\" title=\"struct serde_json::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"vodozemac/megolm/enum.InboundGroupSessionUnpicklingError.html\" title=\"enum vodozemac::megolm::InboundGroupSessionUnpicklingError\">InboundGroupSessionUnpicklingError</a>","synthetic":false,"types":["vodozemac::megolm::inbound_group_session::InboundGroupSessionUnpicklingError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/serde_json/1.0.78/serde_json/error/struct.Error.html\" title=\"struct serde_json::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"vodozemac/olm/enum.AccountUnpicklingError.html\" title=\"enum vodozemac::olm::AccountUnpicklingError\">AccountUnpicklingError</a>","synthetic":false,"types":["vodozemac::olm::account::AccountUnpicklingError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"vodozemac/olm/enum.MessageType.html\" title=\"enum vodozemac::olm::MessageType\">MessageType</a>&gt; for <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>","synthetic":false,"types":[]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://docs.rs/base64/0.13.0/base64/decode/enum.DecodeError.html\" title=\"enum base64::decode::DecodeError\">DecodeError</a>&gt; for <a class=\"enum\" href=\"vodozemac/olm/enum.DecryptionError.html\" title=\"enum vodozemac::olm::DecryptionError\">DecryptionError</a>","synthetic":false,"types":["vodozemac::olm::session::DecryptionError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/digest/0.10.2/digest/mac/struct.MacError.html\" title=\"struct digest::mac::MacError\">MacError</a>&gt; for <a class=\"enum\" href=\"vodozemac/olm/enum.DecryptionError.html\" title=\"enum vodozemac::olm::DecryptionError\">DecryptionError</a>","synthetic":false,"types":["vodozemac::olm::session::DecryptionError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/block-modes/0.8.1/block_modes/errors/struct.BlockModeError.html\" title=\"struct block_modes::errors::BlockModeError\">BlockModeError</a>&gt; for <a class=\"enum\" href=\"vodozemac/olm/enum.DecryptionError.html\" title=\"enum vodozemac::olm::DecryptionError\">DecryptionError</a>","synthetic":false,"types":["vodozemac::olm::session::DecryptionError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"vodozemac/enum.DecodeError.html\" title=\"enum vodozemac::DecodeError\">DecodeError</a>&gt; for <a class=\"enum\" href=\"vodozemac/olm/enum.DecryptionError.html\" title=\"enum vodozemac::olm::DecryptionError\">DecryptionError</a>","synthetic":false,"types":["vodozemac::olm::session::DecryptionError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"vodozemac/olm/struct.SessionPickle.html\" title=\"struct vodozemac::olm::SessionPickle\">SessionPickle</a>&gt; for <a class=\"struct\" href=\"vodozemac/olm/struct.Session.html\" title=\"struct vodozemac::olm::Session\">Session</a>","synthetic":false,"types":["vodozemac::olm::session::Session"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/digest/0.10.2/digest/mac/struct.MacError.html\" title=\"struct digest::mac::MacError\">MacError</a>&gt; for <a class=\"enum\" href=\"vodozemac/sas/enum.SasError.html\" title=\"enum vodozemac::sas::SasError\">SasError</a>","synthetic":false,"types":["vodozemac::sas::SasError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt; for <a class=\"enum\" href=\"vodozemac/enum.LibolmUnpickleError.html\" title=\"enum vodozemac::LibolmUnpickleError\">LibolmUnpickleError</a>","synthetic":false,"types":["vodozemac::LibolmUnpickleError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://docs.rs/base64/0.13.0/base64/decode/enum.DecodeError.html\" title=\"enum base64::decode::DecodeError\">DecodeError</a>&gt; for <a class=\"enum\" href=\"vodozemac/enum.LibolmUnpickleError.html\" title=\"enum vodozemac::LibolmUnpickleError\">LibolmUnpickleError</a>","synthetic":false,"types":["vodozemac::LibolmUnpickleError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"vodozemac/enum.PublicKeyError.html\" title=\"enum vodozemac::PublicKeyError\">PublicKeyError</a>&gt; for <a class=\"enum\" href=\"vodozemac/enum.LibolmUnpickleError.html\" title=\"enum vodozemac::LibolmUnpickleError\">LibolmUnpickleError</a>","synthetic":false,"types":["vodozemac::LibolmUnpickleError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"vodozemac/enum.PublicKeyError.html\" title=\"enum vodozemac::PublicKeyError\">PublicKeyError</a>&gt; for <a class=\"enum\" href=\"vodozemac/enum.DecodeError.html\" title=\"enum vodozemac::DecodeError\">DecodeError</a>","synthetic":false,"types":["vodozemac::DecodeError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"vodozemac/enum.SignatureError.html\" title=\"enum vodozemac::SignatureError\">SignatureError</a>&gt; for <a class=\"enum\" href=\"vodozemac/enum.DecodeError.html\" title=\"enum vodozemac::DecodeError\">DecodeError</a>","synthetic":false,"types":["vodozemac::DecodeError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"https://docs.rs/prost/0.9.0/prost/error/struct.DecodeError.html\" title=\"struct prost::error::DecodeError\">DecodeError</a>&gt; for <a class=\"enum\" href=\"vodozemac/enum.DecodeError.html\" title=\"enum vodozemac::DecodeError\">DecodeError</a>","synthetic":false,"types":["vodozemac::DecodeError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"enum\" href=\"https://docs.rs/base64/0.13.0/base64/decode/enum.DecodeError.html\" title=\"enum base64::decode::DecodeError\">DecodeError</a>&gt; for <a class=\"enum\" href=\"vodozemac/enum.DecodeError.html\" title=\"enum vodozemac::DecodeError\">DecodeError</a>","synthetic":false,"types":["vodozemac::DecodeError"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()