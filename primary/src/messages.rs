use crate::batch_maker::Transaction;
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::primary::Round;
use blsttc::{PublicKeyShareG2, SignatureShareG1};
use config::Committee;
use crypto::{
    remove_pubkeys, BlsSignatureService, Digest, Hash, PublicKey, Signature, SignatureService,
};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryInto;
use std::fmt;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Header {
    pub author: PublicKey,
    pub round: Round,
    pub payload: Vec<Transaction>,
    pub parents: Vec<Digest>,
    pub id: Digest,
    pub signature: Signature,
    pub timeout_cert: TimeoutCert,
    pub no_vote_certs: Vec<NoVoteCert>,
}

impl Header {
    pub async fn new(
        author: PublicKey,
        round: Round,
        payload: Vec<Transaction>,
        parents: Vec<Digest>,
        timeout_cert: TimeoutCert,
        no_vote_certs: Vec<NoVoteCert>,
        signature_service: &mut SignatureService,
    ) -> Self {
        let header = Self {
            author,
            round,
            payload,
            parents,
            id: Digest::default(),
            signature: Signature::default(),
            timeout_cert,
            no_vote_certs,
        };
        let id = header.digest();
        let signature = signature_service.request_signature(id.clone()).await;
        Self {
            id,
            signature,
            ..header
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the header id is well formed.
        ensure!(self.digest() == self.id, DagError::InvalidHeaderId);

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));

        // Check the signature.
        self.signature
            .verify(&self.id, &self.author)
            .map_err(DagError::from)

        // Check if pointer to prev leader exists
    }

    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|_| Self { ..Self::default() })
            .collect()
    }
}

impl Hash for Header {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.author);
        hasher.update(self.round.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        // for x in &self.parents {
        //     hasher.update(x);
        // }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}: B{}({})", self.id, self.round, self.author,)
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HeaderWithCertificate {
    pub header: Header,
    pub parents: Vec<Certificate>,
}
impl fmt::Debug for HeaderWithCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({})",
            self.header.id, self.header.round, self.header.author,
        )
    }
}
impl fmt::Display for HeaderWithCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.header.round, self.header.author)
    }
}
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HeaderInfoWithCertificate {
    pub header_info: HeaderInfo,
    pub parents: Vec<Certificate>,
}
impl fmt::Debug for HeaderInfoWithCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({})",
            self.header_info.id, self.header_info.round, self.header_info.author,
        )
    }
}
impl fmt::Display for HeaderInfoWithCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "B{}({})",
            self.header_info.round, self.header_info.author
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct HeaderInfo {
    pub author: PublicKey,
    pub round: Round,
    pub payload: Digest,
    pub parents: Vec<Digest>,
    pub id: Digest,
    pub signature: Signature,
    pub timeout_cert: TimeoutCert,
    pub no_vote_certs: Vec<NoVoteCert>,
}

impl HeaderInfo {
    pub fn create_from(header: &Header) -> Self {
        let header_info = Self {
            author: header.author,
            round: header.round,
            payload: payload_digest(&header),
            parents: header.parents.clone(),
            id: header.id,
            signature: header.signature.clone(),
            timeout_cert: header.timeout_cert.clone(),
            no_vote_certs: header.no_vote_certs.clone(),
        };

        header_info
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author));

        // Check the signature.
        self.signature
            .verify(&self.id, &self.author)
            .map_err(DagError::from)

        // Check if pointer to prev leader exists
    }
}

fn payload_digest(header: &Header) -> Digest {
    let mut hasher = Sha512::new();

    for x in &header.payload {
        hasher.update(x);
    }

    Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
}

impl fmt::Debug for HeaderInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}: B{}({})", self.id, self.round, self.author,)
    }
}

impl fmt::Display for HeaderInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    pub round: Round,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Timeout {
    pub async fn new(
        round: Round,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let timeout = Self {
            round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(timeout.digest()).await;
        Self {
            signature,
            ..timeout
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for Timeout {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.author);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Timeout: R{}({})", self.round, self.author,)
    }
}

impl fmt::Display for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Round {} Timeout by {}", self.round, self.author)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NoVoteMsg {
    pub round: Round,
    pub leader: PublicKey,
    pub author: PublicKey,
    pub signature: Signature,
}

impl NoVoteMsg {
    pub async fn new(
        round: Round,
        leader: PublicKey,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let msg = Self {
            round,
            leader,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(msg.digest()).await;
        Self { signature, ..msg }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for NoVoteMsg {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.author);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for NoVoteMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "NoVoteMsg: R{}({})", self.round, self.author,)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub author: PublicKey,
    pub signature: SignatureShareG1,
}

impl Vote {
    pub async fn new(
        header: &Header,
        author: &PublicKey,
        bls_signature_service: &mut BlsSignatureService,
    ) -> Self {
        let vote = Self {
            id: header.digest(),
            round: header.round,
            origin: header.author,
            author: *author,
            signature: SignatureShareG1::default(),
        };
        let signature = bls_signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub async fn new_for_header_info(
        header_info: &HeaderInfo,
        author: &PublicKey,
        bls_signature_service: &BlsSignatureService,
    ) -> Self {
        let vote = Self {
            id: header_info.id.clone(),
            round: header_info.round,
            origin: header_info.author,
            author: *author,
            signature: SignatureShareG1::default(),
        };
        let signature = bls_signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author)
        );

        let author_bls = committee.get_bls_public_g2(&self.author);

        // Check the signature.
        SignatureShareG1::verify_batch(&self.digest().0, &author_bls, &self.signature)
            .map_err(DagError::from)
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.id);
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.origin);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.digest(),
            self.round,
            self.author,
            self.id
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct TimeoutCert {
    pub round: Round,
    // Stores a list of public keys and their corresponding signatures.
    pub timeouts: Vec<(PublicKey, Signature)>,
}

impl TimeoutCert {
    pub fn new(round: Round) -> Self {
        Self {
            round,
            timeouts: Vec::new(),
        }
    }

    // Adds a timeout to the certificate.
    pub fn add_timeout(&mut self, author: PublicKey, signature: Signature) -> DagResult<()> {
        // Ensure this public key hasn't already submitted a timeout for this round
        if self.timeouts.iter().any(|(pk, _)| *pk == author) {
            return Err(DagError::AuthorityReuse(author));
        }

        // Add the timeout to the list
        self.timeouts.push((author, signature));

        Ok(())
    }

    // Verifies the timeout certificate against the committee.
    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        let mut weight = 0;

        let mut used = HashSet::new();
        for (name, _) in self.timeouts.iter() {
            ensure!(!used.contains(name), DagError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, DagError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }

        // Check if the accumulated weight meets the quorum threshold.
        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct NoVoteCert {
    pub round: Round,
    pub no_votes: Vec<(PublicKey, Signature)>,
}

impl NoVoteCert {
    pub fn new(round: Round) -> Self {
        Self {
            round,
            no_votes: Vec::new(),
        }
    }

    pub fn add_no_vote(&mut self, author: PublicKey, signature: Signature) -> DagResult<()> {
        if self.no_votes.iter().any(|(pk, _)| *pk == author) {
            return Err(DagError::AuthorityReuse(author));
        }

        self.no_votes.push((author, signature));

        Ok(())
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        let mut weight = 0;
        let mut used = HashSet::new();
        for (author, _) in &self.no_votes {
            ensure!(!used.contains(author), DagError::AuthorityReuse(*author));
            let voting_rights = committee.stake(author);
            ensure!(voting_rights > 0, DagError::UnknownAuthority(*author));
            used.insert(*author);
            weight += voting_rights;
        }

        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Certificate {
    pub header_id: Digest,
    pub round: Round,
    pub origin: PublicKey,
    pub votes: (Vec<u128>, SignatureShareG1),
}

impl Certificate {
    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|_| Self { ..Self::default() })
            .collect()
    }

    pub fn verify(
        &self,
        committee: &Committee,
        sorted_keys: &Vec<PublicKeyShareG2>,
        combined_pubkey: &PublicKeyShareG2,
    ) -> DagResult<()> {
        // Genesis certificates are always valid.
        if Self::genesis(committee).contains(self) {
            return Ok(());
        }

        // // Check the embedded header.
        // self.header.verify(committee)?;

        // // Ensure the certificate has a quorum.
        // let mut weight = 0;
        // let mut used = HashSet::new();
        // for (name, _) in self.votes.iter() {
        //     ensure!(!used.contains(name), DagError::AuthorityReuse(*name));
        //     let voting_rights = committee.stake(name);
        //     ensure!(voting_rights > 0, DagError::UnknownAuthority(*name));
        //     used.insert(*name);
        //     weight += voting_rights;
        // }
        // ensure!(
        //     weight >= committee.quorum_threshold(),
        //     DagError::CertificateRequiresQuorum
        // );

        let mut ids = Vec::new();
        for idx in 0..committee.size() {
            let x = idx / 128;
            let chunk = self.votes.0[x];
            let ridx = idx - x * 128;
            if chunk & 1 << ridx != 0 {
                ids.push(idx);
            }
        }
        // let pks: Vec<PublicKeyShareG2> = ids.iter().map(|i| sorted_keys[*i]).collect();
        let agg_pk = remove_pubkeys(&combined_pubkey, ids, &sorted_keys);

        SignatureShareG1::verify_batch(&self.digest().0, &agg_pk, &self.votes.1)
            .map_err(DagError::from)
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn origin(&self) -> PublicKey {
        self.origin
    }
}

impl Hash for Certificate {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.header_id);
        hasher.update(self.round().to_le_bytes());
        hasher.update(&self.origin());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: C{}({}, {})",
            self.digest(),
            self.round(),
            self.origin(),
            self.header_id
        )
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        let mut ret = self.header_id == other.header_id;
        ret &= self.round() == other.round();
        ret &= self.origin() == other.origin();
        ret
    }
}
