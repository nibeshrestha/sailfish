// Copyright(C) Facebook, Inc. and its affiliates.
use ed25519_dalek::ed25519;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, RngCore};
use rand_chacha::rand_core::SeedableRng;
use serde::{de, ser, Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use bls_signatures::{PrivateKey, PublicKey, Serialize as Ser, Signature, Error as BlsError};
use rand_chacha::ChaCha8Rng;

#[cfg(test)]
#[path = "tests/crypto_tests.rs"]
pub mod crypto_tests;

pub type CryptoError = BlsError;

/// Represents a hash digest (32 bytes).
#[derive(Hash, PartialEq, Default, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0).get(0..16).unwrap())
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Digest(item.try_into()?))
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> Digest;
}

// Represents a public key (in bytes).
#[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PubKey(pub [u8; 48]);

impl PubKey {
    pub fn encode_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..48]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }

    pub fn to_pubkey(&self) -> PublicKey {
        let publickey = PublicKey::from_bytes(&self.0).unwrap();
        publickey
    }
}

impl Default for PubKey {
    fn default() -> PubKey {
        Self ([0;48])
    }
}

impl fmt::Debug for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64().get(0..16).unwrap())
    }
}

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for PubKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for PubKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|x| *x = 0);
    }
}


/// Represents a secret key (in bytes).
#[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SecretKey(pub [u8; 32]);

impl Default for SecretKey {
    fn default() -> SecretKey {
        Self ([0;32])
    }
}

impl SecretKey {

    pub fn encode_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64().get(0..16).unwrap())
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|x| *x = 0);
    }
}


pub fn generate_production_keypair() -> (PubKey, SecretKey) {
    
    let mut rng = OsRng;
    let random_number: u64 = rng.next_u64();
    
    let mut rng = ChaCha8Rng::seed_from_u64(random_number);
    let secret_key = PrivateKey::generate(&mut rng);
    let public_key = secret_key.public_key();

    let pubkey = public_key.as_bytes().try_into().unwrap();
    let prikey = secret_key.as_bytes().try_into().unwrap();

    let public_key = PubKey(pubkey);
    let secret_key = SecretKey(prikey);
    (public_key, secret_key)
}


#[derive(Clone, Debug)]
pub struct BlsSignature {
    part1: [u8; 48],
    part2: [u8; 48],
}

impl Default for BlsSignature {
    fn default() -> BlsSignature {
        Self {
            part1 : [0;48],
            part2 : [0;48],
        }
    }
}

impl Serialize for BlsSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for BlsSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl BlsSignature {
    pub fn new(digest: &Digest, secret: &SecretKey) -> Self {
        let sk = PrivateKey::from_bytes(&secret.0).unwrap();
        let sig : [u8;96] = sk.sign(&digest.0).as_bytes().try_into().unwrap();
        let part1 = sig[..48].try_into().expect("Unexpected signature length");
        let part2 = sig[48..96].try_into().expect("Unexpected signature length");
        BlsSignature { part1, part2 }
    }

    pub fn encode_base64(&self) -> String {
        let mut sig: Vec<u8> = Vec::from(&self.part1);
        sig.append(&mut Vec::from(&self.part2));
        base64::encode(sig)
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array1:[u8;48] = bytes[..48]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        let array2:[u8;48] = bytes[48..]
        .try_into()
        .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self{
            part1:array1,
            part2:array2,
        })
    }

    pub fn as_signature(&self) -> Signature {
        let bytes = Vec::from(self.flatten());
        let sign : Signature = Signature::from_bytes(&bytes).unwrap();
        sign
    }

    pub fn flatten(&self) -> [u8; 96] {
        [self.part1, self.part2]
            .concat()
            .try_into()
            .expect("Unexpected signature length")
    }

    pub fn verify(&self, digest: &Digest, public_key: &PubKey) -> Result<(), BlsError> {
        let signature = Signature::from_bytes(&self.flatten()).unwrap();
        let key = PublicKey::from_bytes(&public_key.0).unwrap();
        key.verify(signature, &digest.0);
        Ok(())
    }

    pub fn verify_batch (digest: &Digest, votes: (Vec<PubKey>, Vec<BlsSignature>)) -> Result<(), BlsError>
    {
        for i in 0..votes.0.len() {
            let _ = BlsSignature::verify(&votes.1[i], digest, &votes.0[0]);
        }
        Ok(())
    }
}


/// This service holds the node's private key. It takes digests as input and returns a signature
/// over the digest (through a oneshot channel).
#[derive(Clone)]
pub struct SignatureService {
    channel: Sender<(Digest, oneshot::Sender<BlsSignature>)>,
}

impl SignatureService {
    pub fn new(secret: SecretKey) -> Self {
        let (tx, mut rx): (Sender<(_, oneshot::Sender<_>)>, _) = channel(100);
        tokio::spawn(async move {
            while let Some((digest, sender)) = rx.recv().await {
                let signature = BlsSignature::new(&digest, &secret);
                let _ = sender.send(signature);
            }
        });
        Self { channel: tx }
    }

    pub async fn request_signature(&mut self, digest: Digest) -> BlsSignature {
        let (sender, receiver): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
        if let Err(e) = self.channel.send((digest, sender)).await {
            panic!("Failed to send message BlsSignature Service: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive signature from BlsSignature Service")
    }
}
