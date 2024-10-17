use std::{collections::HashMap, sync::{Arc, RwLock}};

use crate::{
    aggregators::VotesAggregator,
    error::{DagError, DagResult},
    messages::Vote,
    Certificate,
};
use blsttc::PublicKeyShareG2;
use config::{Clan, Committee};
use crypto::Digest;
use log::{debug, info};
use tokio::sync::mpsc::{Receiver, Sender};


pub struct VoteProcessor {
    /// The committee information.
    committee: Arc<Committee>,
    clan: Arc<Clan>,
    sorted_keys: Arc<Vec<PublicKeyShareG2>>,
    combined_pubkey: Arc<PublicKeyShareG2>,
    tx_primary: Arc<Sender<Certificate>>,
    // processing_vote_aggregators: HashMap<Digest, VotesAggregator>,
}

impl VoteProcessor {
    pub fn new(
        committee: Arc<Committee>,
        clan: Arc<Clan>,
        sorted_keys: Arc<Vec<PublicKeyShareG2>>,
        combined_pubkey: Arc<PublicKeyShareG2>,
        tx_primary: Arc<Sender<Certificate>>,
    ) -> Self{
        
            Self {
                committee,
                clan,
                sorted_keys,
                combined_pubkey,
                tx_primary,
            }
    }

    pub async fn process_vote(&self, vote: Vote , processing_vote_aggregators: Arc<RwLock<HashMap<Digest, VotesAggregator>>>) -> DagResult<()> {
            debug!("Processing {:?}", vote);

            if !processing_vote_aggregators.read().unwrap().contains_key(&vote.id) {
                processing_vote_aggregators
                    .write().unwrap().entry(vote.id)
                    .or_insert(VotesAggregator::new(
                        self.sorted_keys.clone(),
                        self.committee.size(),
                    ));
            }

            // Add it to the votes' aggregator and try to make a new certificate.
            if let Some(vote_aggregator) = processing_vote_aggregators.write().unwrap().get_mut(&vote.id) {
                // Add it to the votes' aggregator and try to make a new certificate.
                if let Some(certificate) =
                    vote_aggregator.append(&vote, &self.committee, &self.clan)?
                {
                    info!(
                        "Assembled cert {:?} round {}",
                        certificate.header_id, certificate.round
                    );

                    // Process the new certificate.
                    let committee = Arc::clone(&self.committee);
                    let sorted_keys = Arc::clone(&self.sorted_keys);
                    let tx_primary = Arc::clone(&self.tx_primary);
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
                        let _ = tx_primary.blocking_send(certificate);
                    });
                }
            }
            Ok(())
    }
}
