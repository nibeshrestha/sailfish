// Copyright(C) Facebook, Inc. and its affiliates.
use blsttc::{
    G1Affine, G1Projective, G2Affine, G2Projective, PublicKeyG2, PublicKeyShareG2, SecretKeySet,
    SecretKeyShare, SignatureG1, SignatureShareG1,
};
use ed25519_dalek as dalek;
use ed25519_dalek::ed25519;
use ed25519_dalek::Signer as _;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{de, ser, Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;

#[cfg(test)]
#[path = "tests/crypto_tests.rs"]
pub mod crypto_tests;

pub type CryptoError = ed25519::Error;
pub type BlsError = blsttc::Error;

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

/// Represents a public key (in bytes).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
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

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64().get(0..16).unwrap())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents a secret key (in bytes).
pub struct SecretKey([u8; 64]);

impl SecretKey {
    pub fn encode_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..64]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
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

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|x| *x = 0);
    }
}

pub fn generate_production_keypair() -> (PublicKey, SecretKey) {
    generate_keypair(&mut OsRng)
}

pub fn generate_keypair<R>(csprng: &mut R) -> (PublicKey, SecretKey)
where
    R: CryptoRng + RngCore,
{
    let keypair = dalek::Keypair::generate(csprng);
    let public = PublicKey(keypair.public.to_bytes());
    let secret = SecretKey(keypair.to_bytes());
    (public, secret)
}

/// Represents an ed25519 signature.
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Signature {
    part1: [u8; 32],
    part2: [u8; 32],
}

impl Signature {
    pub fn new(digest: &Digest, secret: &SecretKey) -> Self {
        let keypair = dalek::Keypair::from_bytes(&secret.0).expect("Unable to load secret key");
        let sig = keypair.sign(&digest.0).to_bytes();
        let part1 = sig[..32].try_into().expect("Unexpected signature length");
        let part2 = sig[32..64].try_into().expect("Unexpected signature length");
        Signature { part1, part2 }
    }

    fn flatten(&self) -> [u8; 64] {
        [self.part1, self.part2]
            .concat()
            .try_into()
            .expect("Unexpected signature length")
    }

    pub fn verify(&self, digest: &Digest, public_key: &PublicKey) -> Result<(), CryptoError> {
        let signature = ed25519::signature::Signature::from_bytes(&self.flatten())?;
        let key = dalek::PublicKey::from_bytes(&public_key.0)?;
        key.verify_strict(&digest.0, &signature)
    }

    pub fn verify_batch<'a, I>(digest: &Digest, votes: I) -> Result<(), CryptoError>
    where
        I: IntoIterator<Item = &'a (PublicKey, Signature)>,
    {
        let mut messages: Vec<&[u8]> = Vec::new();
        let mut signatures: Vec<dalek::Signature> = Vec::new();
        let mut keys: Vec<dalek::PublicKey> = Vec::new();
        for (key, sig) in votes.into_iter() {
            messages.push(&digest.0[..]);
            signatures.push(ed25519::signature::Signature::from_bytes(&sig.flatten())?);
            keys.push(dalek::PublicKey::from_bytes(&key.0)?);
        }
        dalek::verify_batch(&messages[..], &signatures[..], &keys[..])
    }
}

/// This service holds the node's private key. It takes digests as input and returns a signature
/// over the digest (through a oneshot channel).
#[derive(Clone)]
pub struct SignatureService {
    channel: Sender<(Digest, oneshot::Sender<Signature>)>,
}

impl SignatureService {
    pub fn new(secret: SecretKey) -> Self {
        let (tx, mut rx): (Sender<(_, oneshot::Sender<_>)>, _) = channel(100);
        tokio::spawn(async move {
            while let Some((digest, sender)) = rx.recv().await {
                let signature = Signature::new(&digest, &secret);
                let _ = sender.send(signature);
            }
        });
        Self { channel: tx }
    }

    pub async fn request_signature(&mut self, digest: Digest) -> Signature {
        let (sender, receiver): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
        if let Err(e) = self.channel.send((digest, sender)).await {
            panic!("Failed to send message Signature Service: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive signature from Signature Service")
    }
}

// #######################################################################
// BLS implementation

#[derive(Serialize, Deserialize)]
pub struct NodeKeyInfo {
    /// The node's public key (and identifier).
    pub nameg2: String,
    /// The node's secret key
    pub secret: String,
}

pub fn create_bls_key_pairs(nodes: usize, threshold: usize, path: String) {
    let mut rng = blsttc::rand::rngs::OsRng;
    // Generate a set of secret key shares
    let sk_set = SecretKeySet::random(threshold, &mut rng);

    // Get the corresponding public key set
    let pk_set_g2 = sk_set.public_keys_g2();

    for node_id in 0..nodes {
        let sk_share = sk_set.secret_key_share(node_id);
        let pk_share_g2 = pk_set_g2.public_key_share(node_id);

        // Create a NodeInfo struct for the current nodes
        let node_info = NodeKeyInfo {
            nameg2: pk_share_g2.encode_base64(),
            secret: sk_share.encode_base64(),
        };

        let id = node_id.to_string();
        let path = path.replace('x', id.as_str());
        let json_data = serde_json::to_string_pretty(&node_info).unwrap();
        std::fs::write(path, json_data).expect("Failed to write JSON data to file");
    }
}

pub fn aggregate_sign(agg_sig: &SignatureShareG1, new_sign: &SignatureShareG1) -> SignatureShareG1 {
    let agg_sign = G1Affine::from(agg_sig.0 .0 + G1Projective::from(new_sign.0 .0));
    let sign = SignatureShareG1(SignatureG1(agg_sign));
    sign
}

pub fn aggregate_pubkey(
    agg_key: &PublicKeyShareG2,
    new_key: &PublicKeyShareG2,
) -> PublicKeyShareG2 {
    let agg_key = G2Affine::from(agg_key.0 .0 + G2Projective::from(new_key.0 .0));
    let key = PublicKeyShareG2(PublicKeyG2(agg_key));
    key
}

pub fn remove_pubkeys(
    agg_key: &PublicKeyShareG2,
    ids: Vec<usize>,
    sorted_keys: &Vec<PublicKeyShareG2>,
) -> PublicKeyShareG2 {
    let mut agg_pub_key = agg_key.clone();
    for i in ids {
        let new_key = G2Affine::from(agg_pub_key.0 .0 - G2Projective::from(sorted_keys[i].0 .0));
        agg_pub_key = PublicKeyShareG2(PublicKeyG2(new_key));
    }
    agg_pub_key
}

pub fn combine_keys(keys: &Vec<PublicKeyShareG2>) -> PublicKeyShareG2 {
    if keys.len() == 1 {
        keys[0]
    } else {
        let mut agg_key = keys[0];
        for i in 1..keys.len() {
            let new_key = G2Affine::from(agg_key.0 .0 + G2Projective::from(keys[i].0 .0));
            agg_key = PublicKeyShareG2(PublicKeyG2(new_key));
        }
        agg_key
    }
}

pub fn combine_key_from_ids(
    ids: Vec<usize>,
    sorted_keys: &Vec<PublicKeyShareG2>,
) -> PublicKeyShareG2 {
    if ids.len() == 1 {
        sorted_keys[ids[0]]
    } else {
        let mut agg_key = sorted_keys[ids[0]];
        for i in 1..ids.len() {
            let new_key =
                G2Affine::from(agg_key.0 .0 + G2Projective::from(sorted_keys[ids[i]].0 .0));
            agg_key = PublicKeyShareG2(PublicKeyG2(new_key));
        }
        agg_key
    }
}

/// This service holds the node's private key. It takes digests as input and returns a signature
/// over the digest (through a oneshot channel).
#[derive(Clone)]
pub struct BlsSignatureService {
    channel: Sender<([u8; 32], oneshot::Sender<SignatureShareG1>)>,
}

impl BlsSignatureService {
    pub fn new(secret: SecretKeyShare) -> Self {
        let (tx, mut rx): (Sender<(_, oneshot::Sender<_>)>, _) = channel(100);
        tokio::spawn(async move {
            while let Some((digest, sender)) = rx.recv().await {
                let signature = SignatureShareG1::new(&digest, &secret);
                let _ = sender.send(signature);
            }
        });
        Self { channel: tx }
    }

    pub async fn request_signature(&mut self, digest: Digest) -> SignatureShareG1 {
        let (sender, receiver): (
            oneshot::Sender<SignatureShareG1>,
            oneshot::Receiver<SignatureShareG1>,
        ) = oneshot::channel();
        if let Err(e) = self.channel.send((digest.0, sender)).await {
            panic!("Failed to send message Signature Service: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive signature from Signature Service")
    }
}
