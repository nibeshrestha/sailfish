// Copyright(C) Facebook, Inc. and its affiliates.
use config::{Committee, Stake};
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use log::{debug, info, log_enabled, warn};
use primary::{Certificate, Header, Round};
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/consensus_tests.rs"]
pub mod consensus_tests;

/// The representation of the DAG in memory.
type Dag = HashMap<Round, HashMap<PublicKey, (Digest, Certificate)>>;

/// The state that needs to be persisted for crash-recovery.
struct State {
    /// The last committed round.
    last_committed_round: Round,
    // Keeps the last committed round for each authority. This map is used to clean up the dag and
    // ensure we don't commit twice the same certificate.
    last_committed: HashMap<PublicKey, Round>,
    /// Keeps the latest committed certificate (and its parents) for every authority. Anything older
    /// must be regularly cleaned up through the function `update`.
    dag: Dag,
}

impl State {
    fn new(genesis: Vec<Certificate>) -> Self {
        let genesis = genesis
            .into_iter()
            .map(|x| (x.origin(), (x.digest(), x)))
            .collect::<HashMap<_, _>>();

        Self {
            last_committed_round: 0,
            last_committed: genesis.iter().map(|(x, (_, y))| (*x, y.round())).collect(),
            dag: [(0, genesis)].iter().cloned().collect(),
        }
    }

    /// Update and clean up internal state base on committed certificates.
    fn update(&mut self, certificate: &Certificate, gc_depth: Round) {
        self.last_committed
            .entry(certificate.origin())
            .and_modify(|r| *r = max(*r, certificate.round()))
            .or_insert_with(|| certificate.round());

        let last_committed_round = *self.last_committed.values().max().unwrap();
        self.last_committed_round = last_committed_round;

        // TODO: This cleanup is dangerous: we need to ensure consensus can receive idempotent replies
        // from the primary. Here we risk cleaning up a certificate and receiving it again later.
        for (name, round) in &self.last_committed {
            self.dag.retain(|r, authorities| {
                authorities.retain(|n, _| n != name || r >= round);
                !authorities.is_empty() && r + gc_depth >= last_committed_round
            });
        }
    }
}

pub struct Consensus {
    /// The committee information.
    committee: Committee,
    /// The depth of the garbage collector.
    gc_depth: Round,

    /// Receives new certificates from the primary. The primary should send us new certificates only
    /// if it already sent us its whole history.
    rx_primary: Receiver<Certificate>,
    /// Receives new headers from the primary.
    rx_primary_header: Receiver<Header>,
    /// Outputs the sequence of ordered certificates to the primary (for cleanup and feedback).
    tx_primary: Sender<Certificate>,
    /// Outputs the sequence of ordered certificates to the application layer.
    tx_output: Sender<Certificate>,

    /// The genesis certificates.
    genesis: Vec<Certificate>,
    /// The stake vote received by the leader of a round.
    stake_vote: HashMap<Round, u32>,
    /// The stake vote received by the sub leaders of a round.
    sub_leaders_stake_vote: HashMap<Round, HashMap<PublicKey, u32>>,
}

impl Consensus {
    pub fn spawn(
        committee: Committee,
        gc_depth: Round,
        rx_primary: Receiver<Certificate>,
        rx_primary_header: Receiver<Header>,
        tx_primary: Sender<Certificate>,
        tx_output: Sender<Certificate>,
    ) {
        tokio::spawn(async move {
            Self {
                committee: committee.clone(),
                gc_depth,
                rx_primary,
                rx_primary_header,
                tx_primary,
                tx_output,
                genesis: Certificate::genesis(&committee),
                stake_vote: HashMap::with_capacity(2 * gc_depth as usize),
                sub_leaders_stake_vote: HashMap::with_capacity(2 * gc_depth as usize),
            }
            .run()
            .await;
        });
    }

    fn update_sub_leaders(&mut self, dag: &Dag, round: Round, header: &Header) -> Vec<Certificate> {
        // Number of leaders might be dynamic, consider parameterizing it if necessary
        // TODO: Change this to input
        let num_leaders = 3;
        let current_leaders = self.committee.sub_leaders(round as usize, num_leaders);
        let mut commitable_leaders = Vec::new();
        let mut push_to_leaders = true;
    
        // Safely access the DAG and update stakes based on valid leader digests in header parents.
        if let Some(round_entries) = dag.get(&round) {
            for leader in current_leaders {
                if let Some((leader_digest, _cert)) = round_entries.get(&leader) {
                    if header.parents.contains(leader_digest) {
                        let stake = self.committee.stake(&header.author);
                        let stake_entry = self.sub_leaders_stake_vote.entry(round).or_default().entry(leader).or_insert(0);
                        *stake_entry += stake;

                        // Check if the updated stake meets the quorum threshold
                        if *stake_entry >= self.committee.quorum_threshold() && push_to_leaders {
                            commitable_leaders.push(_cert.clone());
                        } else {
                            push_to_leaders = false;
                        }
                    }
                }
            }
        }
        commitable_leaders
    }

    fn update_sub_leaders_post_commit(&mut self, dag: &Dag, round: Round, header: &Header) -> Vec<Certificate> {
        // Number of leaders might be dynamic, consider parameterizing it if necessary
        // TODO: Change this to input
        let num_leaders = 3;
        let current_leaders = self.committee.sub_leaders(round as usize, num_leaders);
        let mut commitable_leaders = Vec::new();
        let mut push_to_leaders = true;
    
        // Safely access the DAG and update stakes based on valid leader digests in header parents.
        if let Some(round_entries) = dag.get(&round) {
            for leader in current_leaders {
                if let Some((leader_digest, _cert)) = round_entries.get(&leader) {
                    let stake_entry = self.sub_leaders_stake_vote.entry(round).or_default().entry(leader).or_insert(0);

                    if header.parents.contains(leader_digest) && *stake_entry < self.committee.quorum_threshold() {
                        let stake = self.committee.stake(&header.author);
                        *stake_entry += stake;

                        // Check if the updated stake meets the quorum threshold
                        if *stake_entry >= self.committee.quorum_threshold() && push_to_leaders {
                            commitable_leaders.push(_cert.clone());
                        } else {
                            push_to_leaders = false;
                        }
                    }
                }
            }
        }
        commitable_leaders
    }

    fn prev_commitable_leaders(&self, round: Round, dag: &Dag, certificate: &Certificate) -> Vec<Certificate> {
        // TODO Take as arg
        let num_leaders = 3;
        // Retrieve the current leaders
        let current_leaders = self.committee.sub_leaders(round as usize, num_leaders);
        
        // Initialize a vector to store the valid certificates
        let mut valid_certificates = Vec::new();
        
        // Iterate through the current leaders
        for leader in current_leaders {
            if let Some((_, leader_cert)) = dag.get(&round)
                .and_then(|x| x.get(&leader).map(|(digest, cert)| (digest.clone(), cert.clone())))
            {
                // Check if the leader is linked with the previous leader
                if self.linked(&leader_cert, &certificate, dag) {
                // If linked, add the certificate to the valid certificates vector
                valid_certificates.push(leader_cert);
                }
            }
        }
        
        valid_certificates
    }

    fn is_leader(&self, round: Round, public_key: PublicKey) -> bool {
        // TODO Take as arg
        let num_leaders = 3;

        let current_leaders = self.committee.sub_leaders(round as usize, num_leaders);
        current_leaders.contains(&public_key) || self.committee.leader(round as usize) == public_key
    }

    async fn run(&mut self) {
        // The consensus state (everything else is immutable).
        let mut state = State::new(self.genesis.clone());

        // Listen to incoming certificates and header quorums.
        loop {
            tokio::select! {
                // Listen to incoming headers.
                Some(header) = self.rx_primary_header.recv() => {
                    debug!("Processing {:?}", header);

                    // Try to order the dag to commit. Start from the previous round.
                    let r = header.round - 1;

                    // Get the certificate's digest of the leader. If we already ordered this leader, there is nothing to do.
                    let leader_round = r;
                    if leader_round < state.last_committed_round || leader_round == 0 {
                        continue;
                    }
                    info!("CRAYZ {} {}", leader_round, state.last_committed_round);

                    if leader_round == state.last_committed_round {
                        let commitable_leaders = self.update_sub_leaders_post_commit(&state.dag, leader_round, &header);

                        let mut sequence = Vec::new();

                        for leader in commitable_leaders {
                            // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                            for x in self.order_dag(&leader, &state) {
                                // Update and clean up internal state.
                                state.update(&x, self.gc_depth);
            
                                // Add the certificate to the sequence.
                                sequence.push(x);
                            }
                        }

                        // Output the sequence in the right order.
                        for certificate in sequence {
                            #[cfg(not(feature = "benchmark"))]
                            info!("Committed {} with header", certificate.header);
            
                            #[cfg(feature = "benchmark")]
                            for digest in certificate.header.payload.keys() {
                                // NOTE: This log entry is used to compute performance.
                                info!("Committed Leader {} -> {:?}", certificate.header, digest);
                            }
            
                            self.tx_primary
                                .send(certificate.clone())
                                .await
                                .expect("Failed to send certificate to primary with header");
            
                            if let Err(e) = self.tx_output.send(certificate).await {
                                warn!("Failed to output certificate: {} with header", e);
                            }
                        }

                        continue;
                    }

                    let (leader_digest, leader) = match self.leader(leader_round, &state.dag) {
                        Some(x) => x,
                        None => continue,
                    };

                    if header.parents.contains(leader_digest) {
                        *self.stake_vote.entry(header.round).or_insert(0) += self.committee.stake(&header.author);
                    }
                    let commitable_leaders = self.update_sub_leaders(&state.dag, leader_round, &header);

                    let current_stake = self.stake_vote.get(&header.round);
                    let current_stake_value = *current_stake.unwrap_or(&0);

                    // Commit if we have QT
                    if current_stake_value >= self.committee.quorum_threshold() {
                        // Try committing sub leaders
                        // Get an ordered list of past leaders that are linked to the current leader.
                        debug!("Leader {:?} has enough support with header", leader);
                        let mut sequence = Vec::new();
                        for leader in self.order_leaders(leader, &state).iter().rev() {
                            // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                            for x in self.order_dag(leader, &state) {
                                // Update and clean up internal state.
                                state.update(&x, self.gc_depth);
            
                                // Add the certificate to the sequence.
                                sequence.push(x);
                            }
                        }

                        for leader in commitable_leaders {
                            // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                            for x in self.order_dag(&leader, &state) {
                                // Update and clean up internal state.
                                state.update(&x, self.gc_depth);
            
                                // Add the certificate to the sequence.
                                sequence.push(x);
                            }
                        }
            
                        // Log the latest committed round of every authority (for debug).
                        if log_enabled!(log::Level::Debug) {
                            for (name, round) in &state.last_committed {
                                debug!("Latest commit of {}: Round {} with header", name, round);
                            }
                        }
            
                        // Output the sequence in the right order.
                        for certificate in sequence {
                            #[cfg(not(feature = "benchmark"))]
                            info!("Committed {} with header", certificate.header);
            
                            #[cfg(feature = "benchmark")]
                            for digest in certificate.header.payload.keys() {
                                // NOTE: This log entry is used to compute performance.
                                info!("Committed {} -> {:?}", certificate.header, digest);
                                if self.is_leader(certificate.round(), certificate.origin()) {
                                    info!("Committed Leader {} -> {:?}", certificate.header, digest);
                                } else {
                                    info!("Committed NonLeader {} -> {:?}", certificate.header, digest);
                                }
                            }
            
                            self.tx_primary
                                .send(certificate.clone())
                                .await
                                .expect("Failed to send certificate to primary with header");
            
                            if let Err(e) = self.tx_output.send(certificate).await {
                                warn!("Failed to output certificate: {} with header", e);
                            }
                        }
                    }
                }
                // Listen to incoming certificates.
                Some(certificate) = self.rx_primary.recv() => {
                    debug!("Processing {:?}", certificate);
                    let round = certificate.round();
                    let header = certificate.header();
        
                    // Add the new certificate to the local storage.
                    state
                        .dag
                        .entry(round)
                        .or_insert_with(HashMap::new)
                        .insert(certificate.origin(), (certificate.digest(), certificate));
        
                    // Try to order the dag to commit. Start from the previous round and check if it is a leader round.
                    let r = round - 1;
        
                    // Get the certificate's digest of the leader. If we already ordered this leader, there is nothing to do.
                    let leader_round = r;
                    if leader_round < state.last_committed_round || leader_round == 0 {
                        continue;
                    }

                    if leader_round == state.last_committed_round {
                        let commitable_leaders = self.update_sub_leaders_post_commit(&state.dag, leader_round, &header);

                        let mut sequence = Vec::new();

                        for leader in commitable_leaders {
                            // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                            for x in self.order_dag(&leader, &state) {
                                // Update and clean up internal state.
                                state.update(&x, self.gc_depth);
            
                                // Add the certificate to the sequence.
                                sequence.push(x);
                            }
                        }

                        // Output the sequence in the right order.
                        for certificate in sequence {
                            #[cfg(not(feature = "benchmark"))]
                            info!("Committed {} with header", certificate.header);
            
                            #[cfg(feature = "benchmark")]
                            for digest in certificate.header.payload.keys() {
                                // NOTE: This log entry is used to compute performance.
                                info!("Committed Leader {} -> {:?}", certificate.header, digest);
                            }
            
                            self.tx_primary
                                .send(certificate.clone())
                                .await
                                .expect("Failed to send certificate to primary with header");
            
                            if let Err(e) = self.tx_output.send(certificate).await {
                                warn!("Failed to output certificate: {} with header", e);
                            }
                        }

                        continue;
                    }

                    let (leader_digest, leader) = match self.leader(leader_round, &state.dag) {
                        Some(x) => x,
                        None => continue,
                    };
        
                    // Check if the leader has f+1 support from its children (ie. round r-1).
                    let stake: Stake = state
                        .dag
                        .get(&round)
                        .expect("We should have the whole history by now")
                        .values()
                        .filter(|(_, x)| x.header.parents.contains(leader_digest))
                        .map(|(_, x)| self.committee.stake(&x.origin()))
                        .sum();
        
                    // If it is the case, we can commit the leader. But first, we need to recursively go back to
                    // the last committed leader, and commit all preceding leaders in the right order. Committing
                    // a leader block means committing all its dependencies.
                    if stake < self.committee.validity_threshold() {
                        debug!("Leader {:?} does not have enough support", leader);
                        continue;
                    }
        
                    let commitable_leaders = self.update_sub_leaders(&state.dag, leader_round, &header);

                    // Get an ordered list of past leaders that are linked to the current leader.
                    debug!("Leader {:?} has enough support", leader);
                    let mut sequence = Vec::new();
                    for leader in self.order_leaders(leader, &state).iter().rev() {
                        // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                        for x in self.order_dag(leader, &state) {
                            // Update and clean up internal state.
                            state.update(&x, self.gc_depth);
        
                            // Add the certificate to the sequence.
                            sequence.push(x);
                        }
                    }

                    for leader in commitable_leaders {
                        // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
                        for x in self.order_dag(&leader, &state) {
                            // Update and clean up internal state.
                            state.update(&x, self.gc_depth);
        
                            // Add the certificate to the sequence.
                            sequence.push(x);
                        }
                    }
        
                    // Log the latest committed round of every authority (for debug).
                    if log_enabled!(log::Level::Debug) {
                        for (name, round) in &state.last_committed {
                            debug!("Latest commit of {}: Round {}", name, round);
                        }
                    }
        
                    // Output the sequence in the right order.
                    for certificate in sequence {
                        #[cfg(not(feature = "benchmark"))]
                        info!("Committed {}", certificate.header);
        
                        #[cfg(feature = "benchmark")]
                        for digest in certificate.header.payload.keys() {
                            // NOTE: This log entry is used to compute performance.
                            info!("Committed {} -> {:?}", certificate.header, digest);
                            // if certificate.header.author == self.committee.leader(certificate.header.round as usize) {
                            //     info!("Committed Leader {} -> {:?}", certificate.header, digest);
                            // } else {
                            //     info!("Committed NonLeader {} -> {:?}", certificate.header, digest);
                            // }
                            if self.is_leader(certificate.round(), certificate.origin()) {
                                info!("Committed Leader {} -> {:?}", certificate.header, digest);
                            } else {
                                info!("Committed NonLeader {} -> {:?}", certificate.header, digest);
                            }
                        }
        
                        self.tx_primary
                            .send(certificate.clone())
                            .await
                            .expect("Failed to send certificate to primary");
        
                        if let Err(e) = self.tx_output.send(certificate).await {
                            warn!("Failed to output certificate: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Returns the certificate (and the certificate's digest) originated by the leader of the
    /// specified round (if any).
    fn leader<'a>(&self, round: Round, dag: &'a Dag) -> Option<&'a (Digest, Certificate)> {
        // TODO: We should elect the leader of round r-2 using the common coin revealed at round r.
        // At this stage, we are guaranteed to have 2f+1 certificates from round r (which is enough to
        // compute the coin). We currently just use round-robin.
        #[cfg(test)]
        let seed = 0;
        #[cfg(not(test))]
        let seed = round;

        // Elect the leader.
        let leader = self.committee.leader(seed as usize);

        // Return its certificate and the certificate's digest.
        dag.get(&round).map(|x| x.get(&leader)).flatten()
    }

    /// Order the past leaders that we didn't already commit.
    fn order_leaders(&self, leader: &Certificate, state: &State) -> Vec<Certificate> {
        let mut to_commit = vec![leader.clone()];
        let leader = leader;
        for r in (state.last_committed_round + 1..=leader.round() - 1)
            .rev()
        {
            let prev_leaders = self.prev_commitable_leaders(r, &state.dag, leader);

            // Push all previous leaders in reverse order
            for prev_leader in prev_leaders.iter().rev() {
                to_commit.push(prev_leader.clone());
            }
        }
        to_commit
    }

    /// Checks if there is a path between two leaders.
    fn linked(&self, leader: &Certificate, prev_leader: &Certificate, dag: &Dag) -> bool {
        let mut parents = vec![leader];
        for r in (prev_leader.round()..leader.round()).rev() {
            parents = dag
                .get(&(r))
                .expect("We should have the whole history by now")
                .values()
                .filter(|(digest, _)| parents.iter().any(|x| x.header.parents.contains(digest)))
                .map(|(_, certificate)| certificate)
                .collect();
        }
        parents.contains(&prev_leader)
    }

    /// Flatten the dag referenced by the input certificate. This is a classic depth-first search (pre-order):
    /// https://en.wikipedia.org/wiki/Tree_traversal#Pre-order
    fn order_dag(&self, leader: &Certificate, state: &State) -> Vec<Certificate> {
        debug!("Processing sub-dag of {:?}", leader);
        let mut ordered = Vec::new();
        let mut already_ordered = HashSet::new();

        let mut buffer = vec![leader];
        while let Some(x) = buffer.pop() {
            debug!("Sequencing {:?}", x);
            ordered.push(x.clone());
            for parent in &x.header.parents {
                let (digest, certificate) = match state
                    .dag
                    .get(&(x.round() - 1))
                    .map(|x| x.values().find(|(x, _)| x == parent))
                    .flatten()
                {
                    Some(x) => x,
                    None => continue, // We already ordered or GC up to here.
                };

                // We skip the certificate if we (1) already processed it or (2) we reached a round that we already
                // committed for this authority.
                let mut skip = already_ordered.contains(&digest);
                skip |= state
                    .last_committed
                    .get(&certificate.origin())
                    .map_or_else(|| false, |r| r == &certificate.round());
                if !skip {
                    buffer.push(certificate);
                    already_ordered.insert(digest);
                }
            }
        }

        // Ensure we do not commit garbage collected certificates.
        ordered.retain(|x| x.round() + self.gc_depth >= state.last_committed_round);

        // Ordering the output by round is not really necessary but it makes the commit sequence prettier.
        ordered.sort_by_key(|x| x.round());
        ordered
    }
}
