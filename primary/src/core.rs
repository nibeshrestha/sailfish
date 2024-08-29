// Copyright(C) Facebook, Inc. and its affiliates.
use crate::aggregators::{CertificatesAggregator, NoVoteAggregator, TimeoutAggregator, VotesAggregator};
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, NoVoteCert, NoVoteMsg, Timeout, TimeoutCert, Vote};
use crate::primary::{PrimaryMessage, Round};
use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use bytes::Bytes;
use config::Committee;
use crypto::{BlsSignatureService, Hash as _};
use crypto::{Digest, PublicKey, SignatureService};
use blsttc::PublicKeyShareG2;
use log::{debug, error, info, warn};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub struct Core {
    /// The public key of this primary.
    name: PublicKey,
    name_bls: PublicKeyShareG2,
    /// The committee information.
    committee: Committee,
    sorted_keys: Arc<Vec<PublicKeyShareG2>>,
    /// The persistent storage.
    store: Store,
    /// Handles synchronization with other nodes and our workers.
    synchronizer: Synchronizer,
    /// Service to sign headers.
    signature_service: SignatureService,
    bls_signature_service: BlsSignatureService,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,

    /// Receiver for dag messages (headers, timeouts, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<Header>,
    /// Receives loopback certificates from the `CertificateWaiter`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<Header>,
    /// Receives our newly created timeouts from the `Proposer`.
    rx_timeout: Receiver<Timeout>,
    /// Receives our newly created no vote msgs from the `Proposer`.
    rx_no_vote_msg: Receiver<NoVoteMsg>,
    /// Output all certificates to the consensus layer.
    tx_consensus: Sender<Certificate>,
    /// Send valid a quorum of certificates' ids to the `Proposer` (along with their round).
    tx_proposer: Sender<(Vec<Certificate>, Round)>,
    /// Send a valid TimeoutCertificate along with the round to the `Proposer`.
    tx_timeout_cert: Sender<(TimeoutCert, Round)>,
    /// Send a valid NoVoteCert along with the round to the `Proposer`.
    tx_no_vote_cert: Sender<(NoVoteCert, Round)>,
    /// Send a the header that has voted for the prev leader to the `Consensus` logic.
    tx_consensus_header: Sender<Header>,

    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    // /// The set of headers we are currently processing.
    // processing: HashMap<Round, HashSet<Digest>>,
    // /// The last header we proposed (for which we are waiting votes).
    // current_header: Header,
    // /// Aggregates votes into a certificate.
    // votes_aggregator: VotesAggregator,
    processing_headers: HashMap<Digest, Header>,
    processing_vote_aggregators: HashMap<Digest, VotesAggregator>,
    /// Aggregates certificates to use as parents for new headers.
    certificates_aggregators: HashMap<Round, Box<CertificatesAggregator>>,
    /// A network sender to send the batches to the other workers.
    network: ReliableSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
    /// Aggregates timeouts to use for sending timeout certificate.
    timeouts_aggregators: HashMap<Round, Box<TimeoutAggregator>>,
    /// Aggregates no vote messages to use for sending no vote certificates.
    no_vote_aggregators: HashMap<Round, HashMap<PublicKey, Box<NoVoteAggregator>>>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        name_bls: PublicKeyShareG2,
        committee: Committee,
        sorted_keys: Arc<Vec<PublicKeyShareG2>>,
        store: Store,
        synchronizer: Synchronizer,
        signature_service: SignatureService,
        bls_signature_service: BlsSignatureService,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<Header>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<Header>,
        rx_timeout: Receiver<Timeout>,
        rx_no_vote_msg: Receiver<NoVoteMsg>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<(Vec<Certificate>, Round)>,
        tx_timeout_cert: Sender<(TimeoutCert, Round)>,
        tx_no_vote_cert: Sender<(NoVoteCert, Round)>,
        tx_consensus_header: Sender<Header>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                name_bls,
                committee,
                sorted_keys: sorted_keys,
                store,
                synchronizer,
                signature_service,
                bls_signature_service,
                consensus_round,
                gc_depth,
                rx_primaries,
                rx_header_waiter,
                rx_certificate_waiter,
                rx_proposer,
                rx_timeout,
                rx_no_vote_msg,
                tx_consensus,
                tx_proposer,
                tx_timeout_cert,
                tx_no_vote_cert,
                tx_consensus_header,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                processing_headers: HashMap::new(),
                processing_vote_aggregators: HashMap::new(),
                certificates_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                timeouts_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                no_vote_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
            }
            .run()
            .await;
        });
    }

    async fn process_own_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        // Serialize the Timeout instance into bytes using bincode or a similar serialization tool.
        let bytes = bincode::serialize(&PrimaryMessage::Timeout(timeout.clone()))
            .expect("Failed to serialize own timeout");

        // Broadcast the serialized Timeout to all other primaries.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, info)| info.primary_to_primary)
            .collect();

        // Send the Timeout to each address.
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;

        self.cancel_handlers
            .entry(timeout.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Log the broadcast for debugging purposes.
        debug!("Broadcasted own timeout for round {}", timeout.round);

        self.process_timeout(timeout).await
    }

    async fn process_own_no_vote_msg(&mut self, no_vote_msg: NoVoteMsg) -> DagResult<()> {
        // Serialize the No Vote Msg instance into bytes using bincode or a similar serialization tool.
        let bytes = bincode::serialize(&PrimaryMessage::NoVoteMsg(no_vote_msg.clone()))
            .expect("Failed to serialize own no vote message");

        // Send No Vote Msg to the leader of the round
        let leader_pub_key = self
            .committee
            .leader((no_vote_msg.round + 1) as usize);

        let address = self
            .committee
            .primary(&leader_pub_key)
            .expect("public key not found")
            .primary_to_primary;
        // Send the No Vote Msg to each address.
        let handler = self.network.send(address, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(no_vote_msg.round)
            .or_insert_with(Vec::new)
            .push(handler);

        // Log the broadcast for debugging purposes.
        debug!("Broadcasted own no vote message for round {}", no_vote_msg.round);

        Ok(())
    }

    async fn process_own_header(&mut self, header: Header) -> DagResult<()> {
        // Reset the votes aggregator.
        let sorted_keys = Arc::clone(&self.sorted_keys);
        self.processing_headers
            .entry(header.id.clone())
            .or_insert(header.clone());
        self.processing_vote_aggregators
            .entry(header.id.clone())
            .or_insert(VotesAggregator::new(sorted_keys, self.committee.size()));

        // Broadcast the new header in a reliable manner.
        let addresses = self
            .committee
            .others_primaries(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        let bytes = bincode::serialize(&PrimaryMessage::Header(header.clone()))
            .expect("Failed to serialize our own header");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(header.round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Process the header.
        self.process_header(&header).await
    }

    #[async_recursion]
    async fn process_header(&mut self, header: &Header) -> DagResult<()> {
        debug!("Processing {:?}", header);
        // Send header to consensus
        self.tx_consensus_header.send(header.clone())
            .await
            .expect("Failed to send header to consensus");
        // Indicate that we are processing this header.
        self.processing_headers
            .entry(header.id.clone())
            .or_insert(header.clone());

        // Ensure we have the parents. If at least one parent is missing, the synchronizer returns an empty
        // vector; it will gather the missing parents (as well as all ancestors) from other nodes and then
        // reschedule processing of this header.

        if header.round != 1  {
            let parents = self.synchronizer.get_parents(header).await?;
            if parents.is_empty() {
                debug!("Processing of {} suspended: missing parent(s)", header.id);
                return Ok(());
            }
            info!("{:?}", parents);
            //Check the parent certificates. Ensure the parents form a quorum and are all from the previous round.
            let mut stake = 0;
            let mut has_leader = false;
            for x in parents {
                ensure!(
                    x.round() + 1 == header.round,
                    DagError::MalformedHeader(header.id.clone())
                );
                stake += self.committee.stake(&x.origin());
                
                has_leader = has_leader || self.committee.leader((header.round - 1) as usize).eq(&x.origin);
            }
            ensure!(
                stake >= self.committee.quorum_threshold(),
                DagError::HeaderRequiresQuorum(header.id.clone())
            );

            if !has_leader {
                header.timeout_cert.verify(&self.committee)?;
                if self.committee.leader(header.round as usize).eq(&header.author) {
                    for nvc in header.no_vote_certs.clone() {
                        nvc.verify(&self.committee)?;
                    }
                }
            }
        }
        

        
        //NO NEED TO CHECK FOR MISSING PAYLOAD BECAUSE HEADER ITSELF CONTAINS TRANSACTIONS.

        // // Ensure we have the payload. If we don't, the synchronizer will ask our workers to get it, and then
        // // reschedule processing of this header once we have it.
        // if self.synchronizer.missing_payload(header).await? {
        //     debug!("Processing of {} suspended: missing payload", header);
        //     return Ok(());
        // }

        // Store the header.
        let bytes = bincode::serialize(header).expect("Failed to serialize header");
        self.store.write(header.id.to_vec(), bytes).await;

        // Check if we can vote for this header.
        if self
            .last_voted
            .entry(header.round)
            .or_insert_with(HashSet::new)
            .insert(header.author)
        {
            // Make a vote and send it to all nodes
            let vote = Vote::new(header, &self.name, &mut self.bls_signature_service).await;
            // debug!("Created {:?}", vote);
        
            self.process_vote(vote.clone())
                .await
                .expect("Failed to process our own vote");
        
            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, x)| x.primary_to_primary)
                .collect();
            let bytes = bincode::serialize(&PrimaryMessage::Vote(vote))
                .expect("Failed to serialize our own vote");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(header.round)
                .or_insert_with(Vec::new)
                .extend(handlers);
            
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_timeout(&mut self, timeout: Timeout) -> DagResult<()> {
        debug!("Processing {:?}", timeout);

        // Check if we have enough timeout messages to create a timeout cert to propose next header.
        if let Some(timeout_cert) = self
            .timeouts_aggregators
            .entry(timeout.round)
            .or_insert_with(|| Box::new(TimeoutAggregator::new()))
            .append(timeout.clone(), &self.committee)?
        {
            debug!("Aggregated timeout cert {:?}", timeout);
            // Send it to the `Proposer`.
            self.tx_timeout_cert
                .send((timeout_cert, timeout.round))
                .await
                .expect("Failed to send timeout");
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_no_vote_msg(&mut self, no_vote_msg: NoVoteMsg) -> DagResult<()> {
        debug!("Processing {:?}", no_vote_msg);

        // Check if there's already an aggregator for this round, prepare to add if not
        if !self.no_vote_aggregators
        .entry(no_vote_msg.round).
        or_insert_with(|| HashMap::new()).
        contains_key(&no_vote_msg.leader) {
            let initial_no_vote_msg = NoVoteMsg::new(
                no_vote_msg.round,
                no_vote_msg.leader,
                self.name.clone(),
                &mut self.signature_service
            ).await;

            let mut aggregator = NoVoteAggregator::new();
            // Add the initial message to the new aggregator
            aggregator.append(initial_no_vote_msg, &self.committee)?;

            // Insert the new aggregator into the map
            self.no_vote_aggregators
                .entry(no_vote_msg.round)
                .or_insert_with(|| HashMap::new())
                .insert(no_vote_msg.leader, Box::new(aggregator));
        }

        // Check if we have no vote messages to create a no vote cert to propose next header(as a leader).
        if let Some(no_vote_cert) = self
            .no_vote_aggregators
            .entry(no_vote_msg.round)
            .or_insert_with(|| HashMap::new())
            .entry(no_vote_msg.leader)
            .or_insert(Box::new(NoVoteAggregator::new()))
            .append(no_vote_msg.clone(), &self.committee)?
        {
            // Send it to the `Proposer`.
            debug!("Aggregated no vote cert {:?}", no_vote_msg);
            self.tx_no_vote_cert
                .send((no_vote_cert, no_vote_msg.round))
                .await
                .expect("Failed to send no vote message");
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_vote(&mut self, vote: Vote) -> DagResult<()> {
        debug!("Processing {:?}", vote);

        // Add it to the votes' aggregator and try to make a new certificate.
        if let (Some(header), Some(vote_aggregator)) = (
            self.processing_headers.get(&vote.id),
            self.processing_vote_aggregators.get_mut(&vote.id),
        ) {
            // Add it to the votes' aggregator and try to make a new certificate.
            if let Some(certificate) =
            vote_aggregator
                .append(vote, &self.committee, header)?
            {
                debug!("Assembled {:?}", certificate);

                // Broadcast the certificate.
                let addresses = self
                    .committee
                    .others_primaries(&self.name)
                    .iter()
                    .map(|(_, x)| x.primary_to_primary)
                    .collect();
                let bytes = bincode::serialize(&PrimaryMessage::Certificate(certificate.clone()))
                    .expect("Failed to serialize our own certificate");
                let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                self.cancel_handlers
                    .entry(certificate.round())
                    .or_insert_with(Vec::new)
                    .extend(handlers);

                // Process the new certificate.
                self.process_certificate(certificate)
                    .await
                    .expect("Failed to process valid certificate");
            }
        }

        Ok(())
    }

    #[async_recursion]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        debug!("Processing {:?}", certificate);

        // Process the header embedded in the certificate if we haven't already voted for it (if we already
        // voted, it means we already processed it). Since this header got certified, we are sure that all
        // the data it refers to (ie. its payload and its parents) are available. We can thus continue the
        // processing of the certificate even if we don't have them in store right now.

        // NO NEED TO DO THIS BECAUSE WE HAVE REMOVED HEADER OBJECT FROM CERTIFICATE
        // if !self.processing_headers
        // .get(&certificate.header_id).is_some()
        // {
        //     // This function may still throw an error if the storage fails.
        //     self.process_header(&certificate.header).await?;
        // }

        // Ensure we have all the ancestors of this certificate yet. If we don't, the synchronizer will gather
        // them and trigger re-processing of this certificate.
        if !self.synchronizer.deliver_certificate(&certificate).await? {
            debug!(
                "Processing of {:?} suspended: missing ancestors",
                certificate
            );
            return Ok(());
        }

        // Store the certificate.
        let bytes = bincode::serialize(&certificate).expect("Failed to serialize certificate");
        self.store.write(certificate.digest().to_vec(), bytes).await;

        // Check if we have enough certificates to enter a new dag round and propose a header.
        if let Some(parents) = self
            .certificates_aggregators
            .entry(certificate.round())
            .or_insert_with(|| Box::new(CertificatesAggregator::new()))
            .append(certificate.clone(), &self.committee)?
        {
            // Send it to the `Proposer`.
            self.tx_proposer
                .send((parents, certificate.round()))
                .await
                .expect("Failed to send certificate");
        }

        // Send it to the consensus layer.
        let id = certificate.header_id.clone();
        info!("sending certificate {:?} to consensus", id);
        if let Err(e) = self.tx_consensus.send(certificate).await {
            warn!(
                "Failed to deliver certificate {} to the consensus: {}",
                id, e
            );
        }
        self.processing_headers.remove(&id);
        self.processing_vote_aggregators.remove(&id);
        Ok(())
    }

    fn sanitize_header(&mut self, header: &Header) -> DagResult<()> {
        ensure!(
            self.gc_round <= header.round,
            DagError::TooOld(header.id.clone(), header.round)
        );

        // Verify the header's signature.
        header.verify(&self.committee)?;

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.

        Ok(())
    }

    fn sanitize_timeout(&mut self, timeout: &Timeout) -> DagResult<()> {
        ensure!(
            self.gc_round <= timeout.round,
            DagError::TooOld(timeout.digest(), timeout.round)
        );

        // Verify the timeout's signature.
        timeout.verify(&self.committee)?;

        Ok(())
    }

    fn sanitize_no_vote_msg(&mut self, no_vote_msg: &NoVoteMsg) -> DagResult<()> {
        ensure!(
            self.gc_round <= no_vote_msg.round,
            DagError::TooOld(no_vote_msg.digest(), no_vote_msg.round)
        );

        // Verify the no vote message's signature.
        no_vote_msg.verify(&self.committee)?;

        Ok(())
    }

    fn sanitize_vote(&mut self, vote: &Vote) -> DagResult<()> {
        if let Some(header) = self.processing_headers.get(&vote.id) {
            ensure!(
                header.round <= vote.round,
                DagError::TooOld(vote.digest(), vote.round)
            );

            // Ensure we receive a vote on the expected header.
            ensure!(
                vote.id == header.id
                    && vote.origin == header.author
                    && vote.round == header.round,
                DagError::UnexpectedVote(vote.id.clone())
            );
        }
        Ok(())
        // Verify the vote.
        // vote.verify(&self.committee).map_err(DagError::from)
    }

    fn sanitize_certificate(&mut self, certificate: &Certificate) -> DagResult<()> {
        ensure!(
            self.gc_round <= certificate.round(),
            DagError::TooOld(certificate.digest(), certificate.round())
        );

        // Verify the certificate (and the embedded header).
        certificate.verify(&self.committee,&self.sorted_keys).map_err(DagError::from)
        // Ok(())
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::Header(header) => {
                            match self.sanitize_header(&header) {
                                Ok(()) => self.process_header(&header).await,
                                error => error
                            }

                        },
                        PrimaryMessage::Timeout(timeout) => {
                            match self.sanitize_timeout(&timeout) {
                                Ok(()) => self.process_timeout(timeout).await,
                                error => error
                            }

                        },
                        PrimaryMessage::NoVoteMsg(no_vote_msg) => {
                            match self.sanitize_no_vote_msg(&no_vote_msg) {
                                Ok(()) => self.process_no_vote_msg(no_vote_msg).await,
                                error => error
                            }

                        },
                        PrimaryMessage::Vote(vote) => {
                            match self.sanitize_vote(&vote) {
                                Ok(()) => self.process_vote(vote).await,
                                error => error
                            }
                        },
                        PrimaryMessage::Certificate(certificate) => {
                            match self.sanitize_certificate(&certificate) {
                                Ok(()) =>  self.process_certificate(certificate).await,
                                error => error
                            }
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header) = self.rx_header_waiter.recv() => self.process_header(&header).await,

                // We receive here loopback certificates from the `CertificateWaiter`. Those are certificates for which
                // we interrupted execution (we were missing some of their ancestors) and we are now ready to resume
                // processing.
                Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate(certificate).await,

                // We also receive here our new headers created by the `Proposer`.
                Some(header) = self.rx_proposer.recv() => self.process_own_header(header).await,
                // We also receive here our timeout created by the `Proposer`.
                Some(timeout) = self.rx_timeout.recv() => self.process_own_timeout(timeout).await,
                // We also receive here our no vote messages created by the `Proposer`.
                Some(no_vote_msg) = self.rx_no_vote_msg.recv() => self.process_own_no_vote_msg(no_vote_msg).await,
            };
            match result {
                Ok(()) => (),
                Err(DagError::StoreError(e)) => {
                    error!("{}", e);
                    panic!("Storage failure: killing node.");
                }
                Err(e @ DagError::TooOld(..)) => debug!("{}", e),
                Err(e) => warn!("{}", e),
            }

            // Cleanup internal state.
            let round = self.consensus_round.load(Ordering::Relaxed);
            if round > self.gc_depth {
                let gc_round = round - self.gc_depth;
                self.last_voted.retain(|k, _| k >= &gc_round);
                self.processing_headers.retain(|_, h| &h.round >= &gc_round);
                self.certificates_aggregators.retain(|k, _| k >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.gc_round = gc_round;
            }
        }
    }
}
