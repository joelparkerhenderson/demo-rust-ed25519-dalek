use rand::rngs::OsRng;

// For signing and verifying
use ed25519_dalek::{Signer, SigningKey, Signature, Verifier, VerifyingKey};

// For serialization to byte arrays
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, KEYPAIR_LENGTH, SIGNATURE_LENGTH};

pub fn main() {
    // Create a message that we will sign.
    let message: &[u8] = b"Hello, World!";

    // Load a random number generator (RNG).
    let mut rng = OsRng{};
    
    // Generate a signing key a.k.a. a keypair
    let signing_key: SigningKey = SigningKey::generate(&mut rng);

    // Sign the message
    let signature: Signature = signing_key.sign(message);
    
    // Get the verifying key a.k.a. the keypair private key.
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // Verify the signature.
    assert!(verifying_key.verify(message, &signature).is_ok());

    // Encode to bytes. Note that the array length constant veriables names are
    // not-quite corrsponding to the signing key function names; we believe this
    // would be good for the crate maintainers to adjust in a future version.
    let signature_bytes: [u8; SIGNATURE_LENGTH] = signature.to_bytes();
    let verifying_key_bytes: [u8; PUBLIC_KEY_LENGTH] = signing_key.verifying_key().to_bytes();
    let signing_key_bytes: [u8; SECRET_KEY_LENGTH] = signing_key.to_bytes();
    let keypair_bytes: [u8; KEYPAIR_LENGTH] = signing_key.to_keypair_bytes();

    // Decode from bytes. Note that the function SigningKey::from_bytes cannot
    // fail, whereas the other functions return a Result with a suitable error. 
    let _signature: Signature = Signature::try_from(&signature_bytes[..]).expect("Signature::try_from");
    let _verifying_key: VerifyingKey = VerifyingKey::from_bytes(&verifying_key_bytes).expect("VerifyingKey::from_bytes");
    let _signing_key: SigningKey = SigningKey::from_bytes(&signing_key_bytes);
    let _signing_key: SigningKey = SigningKey::from_keypair_bytes(&keypair_bytes).expect("SigningKey::from_keypair_bytes");

}
