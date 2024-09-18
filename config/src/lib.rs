// Copyright(C) Facebook, Inc. and its affiliates.
use blsttc::{PublicKeyShareG2, SecretKeyShare};
use crypto::{generate_production_keypair, PublicKey, SecretKey};
use log::info;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::BufWriter;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Node {0} is not in the committee")]
    NotInCommittee(PublicKey),

    #[error("Node {0} is not in the clan")]
    NotInClan(PublicKey),

    #[error("Unknown worker id {0}")]
    UnknownWorker(WorkerId),

    #[error("Failed to read config file '{file}': {message}")]
    ImportError { file: String, message: String },

    #[error("Failed to write config file '{file}': {message}")]
    ExportError { file: String, message: String },
}

pub trait Import: DeserializeOwned {
    fn import(path: &str) -> Result<Self, ConfigError> {
        let reader = || -> Result<Self, std::io::Error> {
            let data = fs::read(path)?;
            Ok(serde_json::from_slice(data.as_slice())?)
        };
        reader().map_err(|e| ConfigError::ImportError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }
}

pub trait Export: Serialize {
    fn export(&self, path: &str) -> Result<(), ConfigError> {
        let writer = || -> Result<(), std::io::Error> {
            let file = OpenOptions::new().create(true).write(true).open(path)?;
            let mut writer = BufWriter::new(file);
            let data = serde_json::to_string_pretty(self).unwrap();
            writer.write_all(data.as_ref())?;
            writer.write_all(b"\n")?;
            Ok(())
        };
        writer().map_err(|e| ConfigError::ExportError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }
}

pub type Stake = u32;
pub type WorkerId = u32;

#[derive(Deserialize, Clone)]
pub struct Parameters {
    // consensus only flag
    pub consensus_only: bool,
    /// The preferred header size. The primary creates a new header when it has enough parents and
    /// enough batches' digests to reach `header_size`. Denominated in bytes.
    pub header_size: usize,
    /// The maximum delay that the primary waits between generating two headers, even if the header
    /// did not reach `max_header_size`. Denominated in ms.
    pub max_header_delay: u64,
    /// The depth of the garbage collection (Denominated in number of rounds).
    pub gc_depth: u64,
    /// The delay after which the synchronizer retries to send sync requests. Denominated in ms.
    pub sync_retry_delay: u64,
    /// Determine with how many nodes to sync when re-trying to send sync-request. These nodes
    /// are picked at random from the committee.
    pub sync_retry_nodes: usize,
    /// The preferred batch size. The workers seal a batch of transactions when it reaches this size.
    /// Denominated in bytes.
    pub batch_size: usize,
    pub tx_size: usize,
    /// The delay after which the workers seal a batch of transactions, even if `max_batch_size`
    /// is not reached. Denominated in ms.
    pub max_batch_delay: u64,
    pub leaders_per_round: usize,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            consensus_only: false,
            header_size: 1_000,
            max_header_delay: 100,
            gc_depth: 50,
            sync_retry_delay: 5_000,
            sync_retry_nodes: 3,
            batch_size: 500_000,
            tx_size: 512,
            max_batch_delay: 100,
            leaders_per_round: 3,
        }
    }
}

impl Import for Parameters {}

impl Parameters {
    pub fn log(&self) {
        if self.consensus_only {
            info!("Running consensus in isolation");
        }
        info!("Header size set to {} B", self.header_size);
        info!("Max header delay set to {} ms", self.max_header_delay);
        info!("Garbage collection depth set to {} rounds", self.gc_depth);
        info!("Sync retry delay set to {} ms", self.sync_retry_delay);
        info!("Sync retry nodes set to {} nodes", self.sync_retry_nodes);
        info!("Batch size set to {} B", self.batch_size);
        info!("Max batch delay set to {} ms", self.max_batch_delay);
        info!("Leaders per round set to {}", self.leaders_per_round);
    }
}

#[derive(Clone, Deserialize)]
pub struct PrimaryAddresses {
    /// Address to receive messages from other primaries (WAN).
    pub primary_to_primary: SocketAddr,
    /// Address to receive messages from our workers (LAN).
    pub worker_to_primary: SocketAddr,
}

#[derive(Clone, Deserialize, Eq, Hash, PartialEq)]
pub struct WorkerAddresses {
    /// Address to receive client transactions (WAN).
    pub transactions: SocketAddr,
    /// Address to receive messages from other workers (WAN).
    pub worker_to_worker: SocketAddr,
    /// Address to receive messages from our primary (LAN).
    pub primary_to_worker: SocketAddr,
}

#[derive(Clone, Deserialize)]
pub struct Authority {
    pub bls_pubkey_g2: PublicKeyShareG2,
    pub is_clan_member: bool,
    /// The voting power of this authority
    pub stake: Stake,
    /// The network addresses of the primary.
    pub primary: PrimaryAddresses,
    /// Map of workers' id and their network addresses.
    pub workers: HashMap<WorkerId, WorkerAddresses>,
}

#[derive(Clone, Deserialize)]
pub struct Committee {
    pub authorities: BTreeMap<PublicKey, Authority>,
}

impl Import for Committee {}

impl Committee {
    /// Returns the number of authorities.
    pub fn size(&self) -> usize {
        self.authorities.len()
    }

    /// Return the stake of a specific authority.
    pub fn stake(&self, name: &PublicKey) -> Stake {
        self.authorities.get(name).map_or_else(|| 0, |x| x.stake)
    }

    /// Returns the stake of all authorities except `myself`.
    pub fn others_stake(&self, myself: &PublicKey) -> Vec<(PublicKey, Stake)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .map(|(name, authority)| (*name, authority.stake))
            .collect()
    }

    /// Returns the stake required to reach a quorum (2f+1).
    pub fn quorum_threshold(&self) -> Stake {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (2 N + 3) / 3 = 2f + 1 + (2k + 2)/3 = 2f + 1 + k = N - f
        let total_votes: Stake = self.authorities.values().map(|x| x.stake).sum();
        2 * total_votes / 3 + 1
    }

    /// Returns the stake required to reach availability (f+1).
    pub fn validity_threshold(&self) -> Stake {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (N + 2) / 3 = f + 1 + k/3 = f + 1
        let total_votes: Stake = self.authorities.values().map(|x| x.stake).sum();
        (total_votes + 2) / 3
    }

    /// Returns a leader node in a round-robin fashion.
    /// This does not have to be changed because it works for odd and even numbers.
    pub fn leader(&self, seed: usize) -> PublicKey {
        let mut keys: Vec<_> = self.authorities.keys().cloned().collect();
        keys.sort();
        keys[seed % self.size()]
    }

    pub fn sub_leaders(&self, seed: usize, num_leaders: usize) -> Vec<PublicKey> {
        let mut keys: Vec<_> = self.authorities.keys().cloned().collect();
        keys.sort();

        // Find the index of the seed in the sorted keys vector
        let seed_index = seed % self.size();

        // Collect the subsequent num_leader-1 pubKeys in the sorted array from the seed
        let mut sub_leaders = Vec::with_capacity(num_leaders - 1);
        for i in 1..num_leaders {
            let index = (seed_index + i) % self.size(); // Wrap around if needed
            sub_leaders.push(keys[index].clone());
        }

        sub_leaders
    }

    pub fn leader_list(&self, leaders_per_round: usize, seed: usize) -> Vec<PublicKey> {
        let mut keys: Vec<_> = self.authorities.keys().cloned().collect();
        keys.sort();
        let mut leaders: Vec<PublicKey> = Vec::new();
        for i in 0..leaders_per_round {
            leaders.push(keys[(seed + i) % self.size()]);
        }
        leaders
    }

    /// Returns the primary addresses of the target primary.
    pub fn primary(&self, to: &PublicKey) -> Result<PrimaryAddresses, ConfigError> {
        self.authorities
            .get(to)
            .map(|x| x.primary.clone())
            .ok_or_else(|| ConfigError::NotInCommittee(*to))
    }

    /// Returns the addresses of all primaries except `myself`.
    pub fn others_primaries(&self, myself: &PublicKey) -> Vec<(PublicKey, PrimaryAddresses)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .map(|(name, authority)| (*name, authority.primary.clone()))
            .collect()
    }

    pub fn others_primaries_not_in_clan(
        &self,
        myself: &PublicKey,
    ) -> Vec<(PublicKey, PrimaryAddresses)> {
        self.authorities
            .iter()
            .filter(|(name, authmem)| name != &myself && authmem.is_clan_member != true)
            .map(|(name, authority)| (*name, authority.primary.clone()))
            .collect()
    }

    pub fn clan_members_primaries(&self, myself: &PublicKey) -> Vec<(PublicKey, PrimaryAddresses)> {
        self.authorities
            .iter()
            .filter(|(name, authmem)| name != &myself && authmem.is_clan_member == true)
            .map(|(name, authority)| (*name, authority.primary.clone()))
            .collect()
    }

    /// Returns the addresses of a specific worker (`id`) of a specific authority (`to`).
    pub fn worker(&self, to: &PublicKey, id: &WorkerId) -> Result<WorkerAddresses, ConfigError> {
        self.authorities
            .iter()
            .find(|(name, _)| name == &to)
            .map(|(_, authority)| authority)
            .ok_or_else(|| ConfigError::NotInCommittee(*to))?
            .workers
            .iter()
            .find(|(worker_id, _)| worker_id == &id)
            .map(|(_, worker)| worker.clone())
            .ok_or_else(|| ConfigError::NotInCommittee(*to))
    }

    /// Returns the addresses of all our workers.
    pub fn our_workers(&self, myself: &PublicKey) -> Result<Vec<WorkerAddresses>, ConfigError> {
        self.authorities
            .iter()
            .find(|(name, _)| name == &myself)
            .map(|(_, authority)| authority)
            .ok_or_else(|| ConfigError::NotInCommittee(*myself))?
            .workers
            .values()
            .cloned()
            .map(Ok)
            .collect()
    }

    /// Returns the addresses of all workers with a specific id except the ones of the authority
    /// specified by `myself`.
    pub fn others_workers(
        &self,
        myself: &PublicKey,
        id: &WorkerId,
    ) -> Vec<(PublicKey, WorkerAddresses)> {
        self.authorities
            .iter()
            .filter(|(name, _)| name != &myself)
            .filter_map(|(name, authority)| {
                authority
                    .workers
                    .iter()
                    .find(|(worker_id, _)| worker_id == &id)
                    .map(|(_, addresses)| (*name, addresses.clone()))
            })
            .collect()
    }

    pub fn get_public_keys(&self) -> Vec<PublicKey> {
        self.authorities
            .iter()
            .map(|(name, _)| (name.clone()))
            .collect()
    }
    pub fn get_bls_public_keys(&self) -> Vec<PublicKeyShareG2> {
        self.authorities
            .iter()
            .map(|(_, x)| x.bls_pubkey_g2)
            .collect()
    }

    pub fn get_bls_public_g2(&self, name: &PublicKey) -> PublicKeyShareG2 {
        self.authorities.get(name).map(|x| x.bls_pubkey_g2).unwrap()
    }
}

#[derive(Clone, Deserialize)]
pub struct ClanMember {
    pub bls_pubkey_g2: PublicKeyShareG2,
    pub is_clan_member: bool,
    /// The voting power of this authority
    pub stake: Stake,
    /// The network addresses of the primary.
    pub primary: PrimaryAddresses,
    /// Map of workers' id and their network addresses.
    pub workers: HashMap<WorkerId, WorkerAddresses>,
}

#[derive(Clone, Deserialize)]
pub struct Clan {
    pub members: BTreeMap<PublicKey, ClanMember>,
}

impl Import for Clan {}

impl Clan {
    pub fn create_clan_from_committee(committee: &Committee) -> Result<Self, ConfigError> {
        let mut clan_members = BTreeMap::new();

        for (public_key, authority) in &committee.authorities {
            if authority.is_clan_member {
                let clan_member = ClanMember {
                    bls_pubkey_g2: authority.bls_pubkey_g2,
                    is_clan_member: authority.is_clan_member,
                    stake: authority.stake.clone(),
                    primary: authority.primary.clone(),
                    workers: authority.workers.clone(),
                };
                clan_members.insert(public_key.clone(), clan_member);
            }
        }

        Ok(Clan {
            members: clan_members,
        })
    }

    /// Returns the number of authorities.
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// Return the stake of a specific authority.
    pub fn stake(&self, name: &PublicKey) -> Stake {
        self.members.get(name).map_or_else(|| 0, |x| x.stake)
    }

    /// Returns the stake of all authorities except `myself`.
    pub fn others_stake(&self, myself: &PublicKey) -> Vec<(PublicKey, Stake)> {
        self.members
            .iter()
            .filter(|(name, _)| name != &myself)
            .map(|(name, authority)| (*name, authority.stake))
            .collect()
    }

    /// Returns the stake required to reach a quorum (2f+1).
    pub fn quorum_threshold(&self) -> Stake {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (2 N + 3) / 3 = 2f + 1 + (2k + 2)/3 = 2f + 1 + k = N - f
        let total_votes: Stake = self.members.values().map(|x| x.stake).sum();
        2 * total_votes / 3 + 1
    }

    /// Returns the stake required to reach availability (f+1).
    pub fn validity_threshold(&self) -> Stake {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (N + 2) / 3 = f + 1 + k/3 = f + 1
        let total_votes: Stake = self.members.values().map(|x| x.stake).sum();
        (total_votes + 2) / 3
    }

    /// Returns the primary addresses of the target primary.
    pub fn primary(&self, to: &PublicKey) -> Result<PrimaryAddresses, ConfigError> {
        self.members
            .get(to)
            .map(|x| x.primary.clone())
            .ok_or_else(|| ConfigError::NotInCommittee(*to))
    }

    /// Returns the addresses of all primaries except `myself`.
    pub fn my_clan_other_primaries(
        &self,
        myself: &PublicKey,
    ) -> Vec<(PublicKey, PrimaryAddresses)> {
        self.members
            .iter()
            .filter(|(name, clanmem)| name != &myself)
            .map(|(name, clan_member)| (*name, clan_member.primary.clone()))
            .collect()
    }

    /// Returns the addresses of a specific worker (`id`) of a specific authority (`to`).
    pub fn worker(&self, to: &PublicKey, id: &WorkerId) -> Result<WorkerAddresses, ConfigError> {
        self.members
            .iter()
            .find(|(name, _)| name == &to)
            .map(|(_, authority)| authority)
            .ok_or_else(|| ConfigError::NotInCommittee(*to))?
            .workers
            .iter()
            .find(|(worker_id, _)| worker_id == &id)
            .map(|(_, worker)| worker.clone())
            .ok_or_else(|| ConfigError::NotInCommittee(*to))
    }

    /// Returns the addresses of all our workers.
    pub fn our_workers(&self, myself: &PublicKey) -> Result<Vec<WorkerAddresses>, ConfigError> {
        self.members
            .iter()
            .find(|(name, _)| name == &myself)
            .map(|(_, authority)| authority)
            .ok_or_else(|| ConfigError::NotInCommittee(*myself))?
            .workers
            .values()
            .cloned()
            .map(Ok)
            .collect()
    }

    /// Returns the addresses of all workers with a specific id except the ones of the authority
    /// specified by `myself`.
    pub fn others_workers(
        &self,
        myself: &PublicKey,
        id: &WorkerId,
    ) -> Vec<(PublicKey, WorkerAddresses)> {
        self.members
            .iter()
            .filter(|(name, _)| name != &myself)
            .filter_map(|(name, authority)| {
                authority
                    .workers
                    .iter()
                    .find(|(worker_id, _)| worker_id == &id)
                    .map(|(_, addresses)| (*name, addresses.clone()))
            })
            .collect()
    }

    pub fn get_public_keys(&self) -> Vec<PublicKey> {
        self.members
            .iter()
            .map(|(name, _)| (name.clone()))
            .collect()
    }
    pub fn get_bls_public_keys(&self) -> Vec<PublicKeyShareG2> {
        self.members.iter().map(|(_, x)| x.bls_pubkey_g2).collect()
    }

    pub fn get_bls_public_g2(&self, name: &PublicKey) -> PublicKeyShareG2 {
        self.members.get(name).map(|x| x.bls_pubkey_g2).unwrap()
    }

    pub fn is_member(&self, name: &PublicKey) -> bool {
        self.members.get(name).is_some()
    }
}

#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    /// The node's public key (and identifier).
    pub name: PublicKey,
    /// The node's secret key.
    pub secret: SecretKey,
}

impl Import for KeyPair {}
impl Export for KeyPair {}

impl KeyPair {
    pub fn new() -> Self {
        let (name, secret) = generate_production_keypair();
        Self { name, secret }
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

//bls

#[derive(Clone, Serialize, Deserialize)]
pub struct BlsKeyPair {
    /// The node's public key (and identifier).
    pub nameg2: PublicKeyShareG2,
    /// The node's secret key.
    pub secret: SecretKeyShare,
}

impl Import for BlsKeyPair {}
impl Export for BlsKeyPair {}

impl BlsKeyPair {
    pub fn new(nodes: usize, threshold: usize, path: String, node_id_to_start: usize) {
        crypto::create_bls_key_pairs(nodes, threshold, path, node_id_to_start);
    }
}

impl Default for BlsKeyPair {
    fn default() -> BlsKeyPair {
        Self {
            nameg2: PublicKeyShareG2::default(),
            secret: SecretKeyShare::default(),
        }
    }
}
