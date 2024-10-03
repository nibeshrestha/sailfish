use crate::certificate_handler::CertificateHandler;
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::certificate_waiter::CertificateWaiter;
use crate::core::Core;
use crate::error::DagError;
use crate::garbage_collector::GarbageCollector;
use crate::header_waiter::HeaderWaiter;
use crate::helper::Helper;
use crate::messages::{
    Certificate, Header, HeaderInfo, HeaderInfoWithCertificate, HeaderWithCertificate, NoVoteMsg,
    Timeout, Vote,
};
// use crate::payload_receiver::PayloadReceiver;
use crate::proposer::Proposer;
use crate::synchronizer::Synchronizer;
use crate::vote_processor::VoteProcessor;
use crate::worker::Worker;
use async_trait::async_trait;
use blsttc::PublicKeyShareG2;
use bytes::Bytes;
use config::{BlsKeyPair, Clan, Committee, KeyPair, Parameters, WorkerId};
use crypto::{BlsSignatureService, Digest, PublicKey, SignatureService};
use futures::sink::SinkExt as _;
use log::info;
use network::{MessageHandler, Receiver as NetworkReceiver, Writer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};

/// The default channel capacity for each channel of the primary.
pub const CHANNEL_CAPACITY: usize = 1_000;

/// The round number.
pub type Round = u64;

#[derive(Debug, Serialize, Deserialize)]
pub enum PrimaryMessage {
    HeaderMsg(HeaderMessage),
    Timeout(Timeout),
    NoVoteMsg(NoVoteMsg),
    Vote(Vote),
    Certificate(Certificate),
    VerifiedCertificate(Certificate),
    CertificatesRequest(Vec<Digest>, /* requestor */ PublicKey),
    PayloadRequest(Digest, PublicKey),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum HeaderMessage {
    HeaderWithCertificate(HeaderWithCertificate),
    HeaderInfoWithCertificate(HeaderInfoWithCertificate),
    Header(Header),
    HeaderInfo(HeaderInfo),
}

pub enum ConsensusMessage {
    HeaderInfo(HeaderInfo),
    Certificate(Certificate),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum HeaderType {
    Header(Header),
    HeaderInfo(HeaderInfo),
}

/// The messages sent by the primary to its workers.
#[derive(Debug, Serialize, Deserialize)]
pub enum PrimaryWorkerMessage {
    /// The primary indicates that the worker need to sync the target missing batches.
    Synchronize(Vec<Digest>, /* target */ PublicKey),
    /// The primary indicates a round update.
    Cleanup(Round),
}

/// The messages sent by the workers to their primary.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerPrimaryMessage {
    /// The worker indicates it sealed a new batch.
    OurBatch(Digest, WorkerId),
    /// The worker indicates it received a batch's digest from another authority.
    OthersBatch(Digest, WorkerId),
}

pub struct Primary;

impl Primary {
    pub fn spawn(
        keypair: KeyPair,
        bls_keypair: BlsKeyPair,
        committee: Committee,
        clan: Clan,
        sorted_keys: Vec<PublicKeyShareG2>,
        combined_key: PublicKeyShareG2,
        parameters: Parameters,
        store: Store,
        tx_consensus: Sender<Certificate>,
        rx_consensus: Receiver<Certificate>,
        tx_consensus_header_msg: Sender<ConsensusMessage>,
        leaders_per_round: usize,
    ) {
        // let (tx_others_digests, rx_others_digests) = channel(CHANNEL_CAPACITY);
        let (tx_our_digests, rx_our_digests) = channel(CHANNEL_CAPACITY);
        let (tx_parents, rx_parents) = channel(CHANNEL_CAPACITY);
        let (tx_headers, rx_headers) = channel(CHANNEL_CAPACITY);
        let (tx_timeout, rx_timeout) = channel(CHANNEL_CAPACITY);
        let (tx_timeout_cert, rx_timeout_cert) = channel(CHANNEL_CAPACITY);
        let (tx_no_vote_msg, rx_no_vote_msg) = channel(CHANNEL_CAPACITY);
        let (tx_no_vote_cert, rx_no_vote_cert) = channel(CHANNEL_CAPACITY);
        let (tx_sync_headers, rx_sync_headers) = channel(CHANNEL_CAPACITY);
        let (tx_sync_certificates, rx_sync_certificates) = channel(CHANNEL_CAPACITY);
        let (tx_headers_loopback, rx_headers_loopback) = channel(CHANNEL_CAPACITY);
        let (tx_certificates_loopback, rx_certificates_loopback) = channel(CHANNEL_CAPACITY);
        let (tx_primary_messages, rx_primary_messages) = channel(CHANNEL_CAPACITY);
        let (tx_cert_requests, rx_cert_requests) = channel(CHANNEL_CAPACITY);
        let (tx_vote, rx_vote) = channel(CHANNEL_CAPACITY);
        let (tx_certificate, rx_certificate) = channel(CHANNEL_CAPACITY);
        let (tx_certs, rx_certs) = channel(CHANNEL_CAPACITY);
        // Write the parameters to the logs.
        parameters.log();

        // Parse the public and secret key of this authority.
        let name = keypair.name;
        let _name_bls = bls_keypair.nameg2;
        let secret = keypair.secret;
        let bls_secret = bls_keypair.secret;

        // Atomic variable use to synchronizer all tasks with the latest consensus round. This is only
        // used for cleanup. The only tasks that write into this variable is `GarbageCollector`.
        let consensus_round = Arc::new(AtomicU64::new(0));

        // Spawn the network receiver listening to messages from the other primaries.
        let mut address = committee
            .primary(&name)
            .expect("Our public key or worker id is not in the committee")
            .primary_to_primary;
        address.set_ip("0.0.0.0".parse().unwrap());
        NetworkReceiver::spawn(
            address,
            /* handler */
            PrimaryReceiverHandler {
                tx_primary_messages: tx_primary_messages.clone(),
                tx_vote: tx_vote.clone(),
                tx_cert_requests,
            },
        );
        info!(
            "Primary {} listening to primary messages on {}",
            name, address
        );

        // Spawn the network receiver listening to messages from our workers.
        let mut address = committee
            .primary(&name)
            .expect("Our public key or worker id is not in the committee")
            .worker_to_primary;
        address.set_ip("0.0.0.0".parse().unwrap());
        // NetworkReceiver::spawn(
        //     address,
        //     /* handler */
        //     WorkerReceiverHandler {
        //         tx_our_digests,
        //         tx_others_digests,
        //     },
        // );
        // info!(
        //     "Primary {} listening to workers messages on {}",
        //     name, address
        // );

        if !parameters.consensus_only {
            Worker::spawn(
                name,
                0,
                committee.clone(),
                parameters.clone(),
                tx_our_digests,
            );
        }

        //The `Synchronizer` provides auxiliary methods helping to `Core` to sync.
        let synchronizer = Synchronizer::new(
            name,
            &committee,
            store.clone(),
            /* tx_header_waiter */ tx_sync_headers,
            /* tx_certificate_waiter */ tx_sync_certificates,
        );

        // The `SignatureService` is used to require signatures on specific digests.
        let signature_service = SignatureService::new(secret);
        let bls_signature_service = BlsSignatureService::new(bls_secret);
        let sorted_keys = Arc::new(sorted_keys);
        // The `Core` receives and handles headers, votes, and certificates from the other primaries.
        Core::spawn(
            name,
            Arc::new(committee.clone()),
            Arc::new(clan.clone()),
            sorted_keys.clone(),
            Arc::new(combined_key),
            store.clone(),
            synchronizer,
            signature_service.clone(),
            bls_signature_service,
            consensus_round.clone(),
            parameters.gc_depth,
            tx_primary_messages.clone(),
            /* rx_primaries */ rx_primary_messages,
            /* rx_header_waiter */ rx_headers_loopback,
            /* rx_certificate_waiter */ rx_certificates_loopback,
            /* rx_proposer */ rx_headers,
            rx_timeout,
            rx_no_vote_msg,
            tx_consensus.clone(),
            /* tx_proposer */ tx_parents.clone(),
            tx_timeout_cert,
            tx_no_vote_cert,
            tx_consensus_header_msg,
            tx_certs,
            leaders_per_round,
        );

        VoteProcessor::spawn(
            Arc::new(committee.clone()),
            Arc::new(clan.clone()),
            sorted_keys,
            Arc::new(combined_key),
            rx_vote,
            tx_certificate,
        );

        CertificateHandler::spawn(
            rx_certificate,
            rx_certs,
            tx_consensus,
            tx_parents,
            leaders_per_round,
            parameters.gc_depth,
            committee.clone(),
            consensus_round.clone(),
        );

        // Keeps track of the latest consensus round and allows other tasks to clean up their their internal state
        GarbageCollector::spawn(&name, &committee, consensus_round.clone(), rx_consensus);

        // Receives batch digests from other workers. They are only used to validate headers.
        // PayloadReceiver::spawn(store.clone(), /* rx_workers */ rx_others_digests);

        // Whenever the `Synchronizer` does not manage to validate a header due to missing parent certificates of
        // batch digests, it commands the `HeaderWaiter` to synchronizer with other nodes, wait for their reply, and
        // re-schedule execution of the header once we have all missing data.
        HeaderWaiter::spawn(
            name,
            committee.clone(),
            store.clone(),
            consensus_round,
            parameters.gc_depth,
            parameters.sync_retry_delay,
            parameters.sync_retry_nodes,
            /* rx_synchronizer */ rx_sync_headers,
            /* tx_core */ tx_headers_loopback,
        );

        // The `CertificateWaiter` waits to receive all the ancestors of a certificate before looping it back to the
        // `Core` for further processing.
        CertificateWaiter::spawn(
            store.clone(),
            /* rx_synchronizer */ rx_sync_certificates,
            /* tx_core */ tx_certificates_loopback,
        );

        // When the `Core` collects enough parent certificates, the `Proposer` generates a new header with new batch
        // digests from our workers and it back to the `Core`.
        Proposer::spawn(
            name,
            committee.clone(),
            signature_service,
            parameters.header_size,
            parameters.tx_size,
            parameters.max_header_delay,
            parameters.consensus_only,
            /* rx_core */ rx_parents,
            /* rx_workers */ rx_our_digests,
            /* tx_core */ tx_headers,
            /* tx_core_timeout */ tx_timeout,
            rx_timeout_cert,
            tx_no_vote_msg,
            rx_no_vote_cert,
            parameters.leaders_per_round,
        );

        // The `Helper` is dedicated to reply to certificates requests from other primaries.
        Helper::spawn(committee.clone(), clan, store, rx_cert_requests);

        // NOTE: This log entry is used to compute performance.
        info!(
            "Primary {} successfully booted on {}",
            name,
            committee
                .primary(&name)
                .expect("Our public key or worker id is not in the committee")
                .primary_to_primary
                .ip()
        );
    }
}

/// Defines how the network receiver handles incoming primary messages.
#[derive(Clone)]
struct PrimaryReceiverHandler {
    tx_primary_messages: Sender<PrimaryMessage>,
    tx_vote: Sender<Vote>,
    tx_cert_requests: Sender<(Vec<Digest>, PublicKey)>,
}

#[async_trait]
impl MessageHandler for PrimaryReceiverHandler {
    async fn dispatch(&self, writer: &mut Writer, serialized: Bytes) -> Result<(), Box<dyn Error>> {
        // Reply with an ACK.
        let _ = writer.send(Bytes::from("Ack")).await;

        // Deserialize and parse the message.
        match bincode::deserialize(&serialized).map_err(DagError::SerializationError)? {
            PrimaryMessage::CertificatesRequest(missing, requestor) => self
                .tx_cert_requests
                .send((missing, requestor))
                .await
                .expect("Failed to send primary message"),
            PrimaryMessage::Vote(vote) => {
                self.tx_vote.send(vote).await.expect("Faild to send vote")
            }
            request => self
                .tx_primary_messages
                .send(request)
                .await
                .expect("Failed to send certificate"),
        }
        Ok(())
    }
}

/// Defines how the network receiver handles incoming workers messages.
#[derive(Clone)]
struct WorkerReceiverHandler {
    tx_our_digests: Sender<(Digest, WorkerId)>,
    tx_others_digests: Sender<(Digest, WorkerId)>,
}

#[async_trait]
impl MessageHandler for WorkerReceiverHandler {
    async fn dispatch(
        &self,
        _writer: &mut Writer,
        serialized: Bytes,
    ) -> Result<(), Box<dyn Error>> {
        // Deserialize and parse the message.
        match bincode::deserialize(&serialized).map_err(DagError::SerializationError)? {
            WorkerPrimaryMessage::OurBatch(digest, worker_id) => self
                .tx_our_digests
                .send((digest, worker_id))
                .await
                .expect("Failed to send workers' digests"),
            WorkerPrimaryMessage::OthersBatch(digest, worker_id) => self
                .tx_others_digests
                .send((digest, worker_id))
                .await
                .expect("Failed to send workers' digests"),
        }
        Ok(())
    }
}
