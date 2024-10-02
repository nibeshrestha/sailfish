use std::{collections::HashMap, sync::{Arc}};

// Copyright(C) Facebook, Inc. and its affiliates.
use crate::{
    aggregators::VotesAggregator, error::{DagError, DagResult}, messages::Vote, primary::{HeaderMessage, HeaderType, PrimaryMessage}, HeaderInfo
};
use blsttc::PublicKeyShareG2;
use config::{Clan, Committee};
use crypto::{Digest, PublicKey};
use log::{debug, error, info, warn};
use tokio::sync::mpsc::{Receiver, Sender};

/// A task dedicated to help other authorities by replying to their certificates requests.
pub struct VoteProcessor {
    /// The committee information.
    committee: Arc<Committee>,
    clan: Arc<Clan>,
    sorted_keys : Arc<Vec<PublicKeyShareG2>>,
    combined_pubkey: Arc<PublicKeyShareG2>,
    rx_vote: Receiver<Vote>,
    tx_primary: Sender<PrimaryMessage>,
    processing_vote_aggregators: HashMap<Digest, VotesAggregator>,
}

impl VoteProcessor {
    pub fn spawn(
        committee: Arc<Committee>,
        clan: Arc<Clan>,
        sorted_keys : Arc<Vec<PublicKeyShareG2>>,
        combined_pubkey: Arc<PublicKeyShareG2>,
        rx_vote: Receiver<Vote>,
        tx_primary: Sender<PrimaryMessage>,
    ) {
        tokio::spawn(async move {
            Self {
                committee,
                clan,
                sorted_keys,
                combined_pubkey,
                rx_vote,
                tx_primary,
                processing_vote_aggregators : HashMap::new(),
            }
            .run()
            .await.unwrap();
        });
    }

    async fn run(&mut self) -> DagResult<()>{

        let tx_primary = Arc::new(self.tx_primary.clone());
        while let Some(vote) = self.rx_vote.recv().await {
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
                        info!(
                            "Certificate verified for header {:?} round {:?}",
                            certificate.header_id, certificate.round
                        );
                        let _ =
                            tx_primary.blocking_send(PrimaryMessage::VerifiedCertificate(certificate));
                    });
                    
                    // self.pool.spawn(move || {
                    //     certificate
                    //         .verify(&committee, &sorted_keys, &combined_key)
                    //         .map_err(DagError::from)
                    //         .unwrap();
                    //     info!(
                    //         "Certificate verified for header {:?} round {:?}",
                    //         certificate.header_id, certificate.round
                    //     );
                    //     let _ =
                    //         tx_primary.blocking_send(PrimaryMessage::VerifiedCertificate(certificate));
                    // });

                }

            }
            
        }
        Ok(())
    }
}
