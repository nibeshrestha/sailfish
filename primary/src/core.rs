// Copyright(C) Facebook, Inc. and its affiliates.
use crate::aggregators::{
    CertificatesAggregator, NoVoteAggregator, TimeoutAggregator, VotesAggregator,
};
use crate::error::{DagError, DagResult};
use crate::messages::{
    Certificate, HeaderInfo, HeaderInfoWithCertificate, HeaderWithCertificate, NoVoteCert,
    NoVoteMsg, Timeout, TimeoutCert, Vote,
};
use crate::primary::{ConsensusMessage, HeaderMessage, HeaderType, PrimaryMessage, Round};
use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use blsttc::PublicKeyShareG2;
use bytes::Bytes;
use config::{Clan, Committee};
use crypto::{BlsSignatureService, Hash as _};
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::{CancelHandler, ReliableSender};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

// #[cfg(test)]
// #[path = "tests/core_tests.rs"]
// pub mod core_tests;

pub struct Core {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Arc<Committee>,
    /// The clan information.
    clan: Arc<Clan>,
    /// The vector of sorted keys.
    sorted_keys: Arc<Vec<PublicKeyShareG2>>,
    /// The combined public key.
    combined_pubkey: Arc<PublicKeyShareG2>,
    /// The persistent storage.
    store: Store,
    /// Handles synchronization with other nodes and our workers.
    synchronizer: Synchronizer,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// BLS Service to sign headers.
    bls_signature_service: BlsSignatureService,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,
    /// Sender to loopback messages to self (core)
    tx_primary: Sender<PrimaryMessage>,
    /// Receiver for dag messages (headers, timeouts, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives loopback headers from the `HeaderWaiter`.
    rx_header_waiter: Receiver<HeaderMessage>,
    /// Receives loopback certificates from the `CertificateWaiter`.
    rx_certificate_waiter: Receiver<Certificate>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<HeaderWithCertificate>,
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
    tx_consensus_header_msg: Sender<ConsensusMessage>,
    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicKey>>,
    /// For storing info of header infos in processing
    processing_header_infos: HashMap<Digest, HeaderInfo>,
    /// For storing info of vote aggregators in processing
    processing_vote_aggregators: HashMap<Digest, VotesAggregator>,
    /// For storing info of processed certificates
    processed_certs: HashMap<Round, HashSet<PublicKey>>,
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
    /// Numbers of leader per round
    leaders_per_round: usize,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Arc<Committee>,
        clan: Arc<Clan>,
        sorted_keys: Arc<Vec<PublicKeyShareG2>>,
        combined_pubkey: Arc<PublicKeyShareG2>,
        store: Store,
        synchronizer: Synchronizer,
        signature_service: SignatureService,
        bls_signature_service: BlsSignatureService,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        tx_primary: Sender<PrimaryMessage>,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_header_waiter: Receiver<HeaderMessage>,
        rx_certificate_waiter: Receiver<Certificate>,
        rx_proposer: Receiver<HeaderWithCertificate>,
        rx_timeout: Receiver<Timeout>,
        rx_no_vote_msg: Receiver<NoVoteMsg>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<(Vec<Certificate>, Round)>,
        tx_timeout_cert: Sender<(TimeoutCert, Round)>,
        tx_no_vote_cert: Sender<(NoVoteCert, Round)>,
        tx_consensus_header_msg: Sender<ConsensusMessage>,
        leaders_per_round: usize,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                clan,
                sorted_keys,
                combined_pubkey,
                store,
                synchronizer,
                signature_service,
                bls_signature_service,
                consensus_round,
                gc_depth,
                tx_primary,
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
                tx_consensus_header_msg,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                processing_header_infos: HashMap::new(),
                processing_vote_aggregators: HashMap::new(),
                processed_certs: HashMap::with_capacity(2 * gc_depth as usize),
                certificates_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                network: ReliableSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                timeouts_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                no_vote_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                leaders_per_round,
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
        let leader_pub_key = self.committee.leader((no_vote_msg.round + 1) as usize);

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
        debug!(
            "Broadcasted own no vote message for round {}",
            no_vote_msg.round
        );

        Ok(())
    }

    async fn process_own_header(
        &mut self,
        header_with_certificates: HeaderWithCertificate,
        tx_primary: &Arc<Sender<PrimaryMessage>>,
    ) -> DagResult<()> {
        // Reset the votes aggregator.
        let h_round = header_with_certificates.header.round;
        let parents = header_with_certificates.parents.clone();

        let sorted_keys = Arc::clone(&self.sorted_keys);
        let header_info = HeaderInfo::create_from(&header_with_certificates.header);

        self.processing_header_infos
            .entry(header_info.id)
            .or_insert(header_info.clone());
        self.processing_vote_aggregators
            .entry(header_with_certificates.header.id)
            .or_insert(VotesAggregator::new(sorted_keys, self.committee.size()));

        // Broadcast the new full header in a reliable manner to clan members.
        let addresses: Vec<_>;
        if self.clan.is_member(&self.name) {
            addresses = self.clan.my_clan_other_primaries(&self.name);
        } else {
            addresses = self.committee.clan_members_primaries(&self.name);
        }

        let addresses = addresses
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();
        let header_msg = HeaderMessage::HeaderWithCertificate(header_with_certificates);
        let bytes = bincode::serialize(&PrimaryMessage::HeaderMsg(header_msg))
            .expect("Failed to serialize our own header");
        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(h_round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Broadcast the new header info in a reliable manner to non clan members.
        let header_info_with_parents = HeaderInfoWithCertificate {
            header_info,
            parents,
        };

        let header_info_msg: HeaderMessage =
            HeaderMessage::HeaderInfoWithCertificate(header_info_with_parents);
        let bytes = bincode::serialize(&PrimaryMessage::HeaderMsg(header_info_msg.clone()))
            .expect("Failed to serialize our own header info");

        let addresses = self
            .committee
            .others_primaries_not_in_clan(&self.name)
            .iter()
            .map(|(_, x)| x.primary_to_primary)
            .collect();

        let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
        self.cancel_handlers
            .entry(h_round)
            .or_insert_with(Vec::new)
            .extend(handlers);

        // Process the header.
        self.process_header_msg(&header_info_msg, tx_primary).await
    }

    async fn process_parent_certificates(
        &mut self,
        parent_certs: &Vec<Certificate>,
    ) -> DagResult<()> {
        for certificate in parent_certs {
            if self
                .processed_certs
                .entry(certificate.round)
                .or_insert_with(HashSet::new)
                .insert(certificate.origin())
            {
                // Check if we have enough certificates to enter a new dag round and propose a header.
                if let Some(parents) = self
                    .certificates_aggregators
                    .entry(certificate.round())
                    .or_insert_with(|| Box::new(CertificatesAggregator::new()))
                    .append(&certificate, &self.committee, self.leaders_per_round)?
                {
                    // Send it to the `Proposer`.
                    self.tx_proposer
                        .send((parents, certificate.round()))
                        .await
                        .expect("Failed to send certificate");
                }
                let id = certificate.header_id;
                if let Err(e) = self
                    .tx_consensus_header_msg
                    .send(ConsensusMessage::Certificate(certificate.clone()))
                    .await
                {
                    warn!(
                        "Failed to deliver certificate {} to the consensus: {}",
                        id, e
                    );
                }
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_header_msg(
        &mut self,
        header_msg: &HeaderMessage,
        tx_primary: &Arc<Sender<PrimaryMessage>>,
    ) -> DagResult<()> {
        debug!("Processing {:?}", header_msg);
        let header_info: HeaderInfo;

        match header_msg {
            HeaderMessage::HeaderWithCertificate(header_with_parents) => {
                self.process_parent_certificates(&header_with_parents.parents)
                    .await?;
                header_info = HeaderInfo::create_from(&header_with_parents.header);
            }
            HeaderMessage::HeaderInfoWithCertificate(header_info_with_parents) => {
                self.process_parent_certificates(&header_info_with_parents.parents)
                    .await?;
                header_info = header_info_with_parents.header_info.clone();
            }
            HeaderMessage::Header(header) => {
                header_info = HeaderInfo::create_from(&header);
            }
            HeaderMessage::HeaderInfo(h_info) => {
                header_info = h_info.clone();
            }
        }
        info!("received header {:?} round {}", header_info.id, header_info.round);

        // Indicate that we are processing this header.
        self.processing_header_infos
            .entry(header_info.id)
            .or_insert(header_info.clone());
        self.processing_vote_aggregators
            .entry(header_info.id)
            .or_insert(VotesAggregator::new(
                self.sorted_keys.clone(),
                self.committee.size(),
            ));

        // Check if we can vote for this header.
        if self
            .last_voted
            .entry(header_info.round)
            .or_insert_with(HashSet::new)
            .insert(header_info.author)
        {
            // Make a vote and send it to all nodes
            let vote = Vote::new_for_header_info(
                &header_info,
                &self.name,
                &mut self.bls_signature_service,
            )
            .await;
            // debug!("Created {:?}", vote);

            let addresses = self
                .committee
                .others_primaries(&self.name)
                .iter()
                .map(|(_, x)| x.primary_to_primary)
                .collect();
            let bytes = bincode::serialize(&PrimaryMessage::Vote(vote.clone()))
                .expect("Failed to serialize our own vote");
            let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
            self.cancel_handlers
                .entry(header_info.round)
                .or_insert_with(Vec::new)
                .extend(handlers);

            self.process_vote(&vote, tx_primary)
                .await
                .expect("Failed to process our own vote");
        }

        // Ensure we have the parents. If at least one parent is missing, the synchronizer returns an empty
        // vector; it will gather the missing parents (as well as all ancestors) from other nodes and then
        // reschedule processing of this header.

        if header_info.round != 1 {
            let parents = self
                .synchronizer
                .get_parents(&HeaderType::HeaderInfo(header_info.clone()))
                .await?;
            if parents.is_empty() {
                debug!(
                    "Processing of {} suspended: missing parent(s)",
                    header_info.id
                );
                return Ok(());
            }
        }

        // Send header to consensus
        self.tx_consensus_header_msg
            .send(ConsensusMessage::HeaderInfo(header_info.clone()))
            .await
            .expect("Failed to send header to consensus");

        let hid = header_info.id;
        // Store the header.
        let header_type = HeaderType::HeaderInfo(header_info);
        let bytes = bincode::serialize(&header_type).expect("Failed to serialize header");
        self.store.write(hid.to_vec(), bytes).await;

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
        if !self
            .no_vote_aggregators
            .entry(no_vote_msg.round)
            .or_insert_with(|| HashMap::new())
            .contains_key(&no_vote_msg.leader)
        {
            let initial_no_vote_msg = NoVoteMsg::new(
                no_vote_msg.round,
                no_vote_msg.leader,
                self.name.clone(),
                &mut self.signature_service,
            )
            .await;

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
    async fn process_vote(
        &mut self,
        vote: &Vote,
        tx_primary: &Arc<Sender<PrimaryMessage>>,
    ) -> DagResult<()> {
        debug!("Processing {:?}", vote);

        if !self.processing_vote_aggregators.contains_key(&vote.id) {
            self.processing_vote_aggregators
                .entry(vote.id)
                .or_insert(VotesAggregator::new(
                    self.sorted_keys.clone(),
                    self.committee.size(),
                ));
        }

        // Add it to the votes' aggregator and try to make a new certificate.
        if let Some(vote_aggregator) = self.processing_vote_aggregators.get_mut(&vote.id) {
            // Add it to the votes' aggregator and try to make a new certificate.
            if let Some(certificate) = vote_aggregator.append(&vote, &self.committee, &self.clan)? {
                debug!("Assembled {:?}", certificate);
                info!("Assembled cert {:?} round {}", certificate.header_id, certificate.round);

                // // Broadcast the certificate.
                // let addresses = self
                //     .committee
                //     .others_primaries(&self.name)
                //     .iter()
                //     .map(|(_, x)| x.primary_to_primary)
                //     .collect();
                // let bytes = bincode::serialize(&PrimaryMessage::Certificate(certificate.clone()))
                //     .expect("Failed to serialize our own certificate");
                // let handlers = self.network.broadcast(addresses, Bytes::from(bytes)).await;
                // self.cancel_handlers
                //     .entry(certificate.round())
                //     .or_insert_with(Vec::new)
                //     .extend(handlers);

                // Process the new certificate.
                let committee = Arc::clone(&self.committee);
                let sorted_keys = Arc::clone(&self.sorted_keys);
                let tx_primary = Arc::clone(&tx_primary);
                let combined_key = Arc::clone(&self.combined_pubkey);

                tokio::task::spawn_blocking(move || {
                    certificate
                        .verify(&committee, &sorted_keys, &combined_key)
                        .map_err(DagError::from)
                        .unwrap();
                    debug!(
                        "Certificate verified for header {:?} round {:?}",
                        certificate.header_id, certificate.round
                    );
                    let _ =
                        tx_primary.blocking_send(PrimaryMessage::VerifiedCertificate(certificate));
                });
            }
        }

        Ok(())
    }

    #[async_recursion]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        debug!("Processing {:?}", certificate);
        info!("verified cert {:?} round {}", certificate.header_id, certificate.round);

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
            .append(&certificate, &self.committee, self.leaders_per_round)?
        {
            // Send it to the `Proposer`.
            self.tx_proposer
                .send((parents, certificate.round()))
                .await
                .expect("Failed to send certificate");
        }

        if self
            .processed_certs
            .entry(certificate.round)
            .or_insert_with(HashSet::new)
            .insert(certificate.origin())
        {
            // Send it to the consensus layer.
            let id = certificate.header_id;
            debug!("sending certificate {:?} to consensus", id);
            if let Err(e) = self.tx_consensus.send(certificate).await {
                warn!(
                    "Failed to deliver certificate {} to the consensus: {}",
                    id, e
                );
            }
        }
        Ok(())
    }

    fn sanitize_header_msg(&mut self, header_msg: &HeaderMessage) -> DagResult<()> {
        match header_msg {
            HeaderMessage::HeaderWithCertificate(header_with_parents) => {
                let header = &header_with_parents.header;
                ensure!(
                    self.gc_round <= header.round,
                    DagError::TooOld(header.id, header.round)
                );
                // Verify the header's signature.
                header.verify(&self.committee)?;
                Ok(())
            }
            HeaderMessage::HeaderInfoWithCertificate(header_info_with_parents) => {
                let header_info = &header_info_with_parents.header_info;
                ensure!(
                    self.gc_round <= header_info.round,
                    DagError::TooOld(header_info.id, header_info.round)
                );
                // Verify the header's signature.
                header_info.verify(&self.committee)?;
                Ok(())
            }
            HeaderMessage::Header(header) => {
                ensure!(
                    self.gc_round <= header.round,
                    DagError::TooOld(header.id, header.round)
                );

                // Verify the header's signature.
                header.verify(&self.committee)?;
                Ok(())
            }

            HeaderMessage::HeaderInfo(header_info) => {
                ensure!(
                    self.gc_round <= header_info.round,
                    DagError::TooOld(header_info.id, header_info.round)
                );

                // Verify the header's signature.
                header_info.verify(&self.committee)?;
                Ok(())
            }
        }

        // TODO [issue #3]: Prevent bad nodes from sending junk headers with high round numbers.
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
        if let Some(header_info) = self.processing_header_infos.get(&vote.id) {
            ensure!(
                header_info.round <= vote.round,
                DagError::TooOld(vote.digest(), vote.round)
            );

            // Ensure we receive a vote on the expected header.
            ensure!(
                vote.id == header_info.id
                    && vote.origin == header_info.author
                    && vote.round == header_info.round,
                DagError::UnexpectedVote(vote.id)
            );
        }
        Ok(())
        // Verify the vote.
        // vote.verify(&self.committee).map_err(DagError::from)
    }

    fn sanitize_certificate(
        &mut self,
        certificate: &Certificate,
        tx_primary: &Arc<Sender<PrimaryMessage>>,
    ) -> DagResult<()> {
        ensure!(
            self.gc_round <= certificate.round(),
            DagError::TooOld(certificate.digest(), certificate.round())
        );

        // if !self.processed_headers.contains(&certificate.header_id) {
        //     // Verify the certificate (and the embedded header).
        //     let committee = Arc::clone(&self.committee);
        //     let sorted_keys = Arc::clone(&self.sorted_keys);
        //     let tx_primary = tx_primary.clone();
        //     let combined_key = Arc::clone(&self.combined_pubkey);

        //     tokio::task::spawn_blocking(move || {
        //         certificate
        //             .verify(&committee, &sorted_keys, &combined_key)
        //             .map_err(DagError::from)
        //             .unwrap();
        //         info!(
        //             "ExtCertificate verified for header {:?} round {:?}",
        //             certificate.header_id, certificate.round
        //         );
        //         let _ = tx_primary.blocking_send(PrimaryMessage::VerifiedCertificate(certificate));
        //     });
        // }

        Ok(())
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        let tx_primary = Arc::new(self.tx_primary.clone());
        let sender_channel = tx_primary.clone();

        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::HeaderMsg(header_msg) => {
                            match self.sanitize_header_msg(&header_msg) {
                                Ok(()) => self.process_header_msg(&header_msg, &sender_channel).await,
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
                                Ok(()) => self.process_vote(&vote, &sender_channel).await,
                                error => error

                            }
                        },
                        PrimaryMessage::Certificate(certificate) => {
                            let res = self.sanitize_certificate(&certificate, &sender_channel);
                            res
                        },
                        PrimaryMessage::VerifiedCertificate(certificate) => {
                            let res = self.process_certificate(certificate).await;
                            res
                        },
                        _ => panic!("Unexpected core message")
                    }
                },

                // We receive here loopback headers from the `HeaderWaiter`. Those are headers for which we interrupted
                // execution (we were missing some of their dependencies) and we are now ready to resume processing.
                Some(header) = self.rx_header_waiter.recv() => self.process_header_msg(&header, &sender_channel).await,

                // We receive here loopback certificates from the `CertificateWaiter`. Those are certificates for which
                // we interrupted execution (we were missing some of their ancestors) and we are now ready to resume
                // processing.
                Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate(certificate).await,

                // We also receive here our new headers created by the `Proposer`.
                Some(header_with_parents) = self.rx_proposer.recv() => self.process_own_header(header_with_parents, &sender_channel).await,
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
                self.processing_header_infos
                    .retain(|_, h| &h.round >= &gc_round);
                self.certificates_aggregators.retain(|k, _| k >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.gc_round = gc_round;
            }
        }
    }
}
