use crate::{
    aggregators::VotesAggregator,
    error::{DagError, DagResult},
    messages::Vote,
    Certificate,
};
use blsttc::PublicKeyShareG2;
use config::{Clan, Committee};
use crypto::Digest;
use dashmap::DashMap;
use log::{debug, info};
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};

pub struct VoteProcessor {
    /// The committee information.
    committee: Arc<Committee>,
    clan: Arc<Clan>,
    sorted_keys: Arc<Vec<PublicKeyShareG2>>,
    combined_pubkey: Arc<PublicKeyShareG2>,
    tx_certificate_handler: Arc<Sender<Certificate>>,
    processing_vote_aggregators: DashMap<Digest, VotesAggregator>,
}

impl VoteProcessor {
    pub fn new(
        committee: Arc<Committee>,
        clan: Arc<Clan>,
        sorted_keys: Arc<Vec<PublicKeyShareG2>>,
        combined_pubkey: Arc<PublicKeyShareG2>,
        tx_certificate_handler: Arc<Sender<Certificate>>,
    ) -> Self {
        Self {
            committee,
            clan,
            sorted_keys,
            combined_pubkey,
            tx_certificate_handler,
            processing_vote_aggregators: DashMap::new(),
        }
    }

    pub async fn process_vote(&self, vote: Vote) -> DagResult<()> {
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
        if let Some(mut vote_aggregator) = self.processing_vote_aggregators.get_mut(&vote.id) {
            // Add it to the votes' aggregator and try to make a new certificate.
            if let Some(certificate) = vote_aggregator.append(&vote, &self.committee, &self.clan)? {
                info!(
                    "Assembled cert {:?} round {}",
                    certificate.header_id, certificate.round
                );

                // Process the new certificate.
                let committee = Arc::clone(&self.committee);
                let sorted_keys = Arc::clone(&self.sorted_keys);
                let tx_certificate_handler = Arc::clone(&self.tx_certificate_handler);
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
                    let _ = tx_certificate_handler.blocking_send(certificate);
                });
            }
        }
        Ok(())
    }
}
