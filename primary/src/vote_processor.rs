use crate::{
    aggregators::VotesAggregator,
    error::{DagError, DagResult},
    messages::Vote,
    Certificate,
};
use blsttc::PublicKeyShareG2;
use config::Committee;
use crypto::Digest;
use log::debug;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc::{Receiver, Sender};
/// A task dedicated to help other authorities by replying to their certificates requests.
pub struct VoteProcessor {
    /// The committee information.
    committee: Arc<Committee>,
    sorted_keys: Arc<Vec<PublicKeyShareG2>>,
    combined_pubkey: Arc<PublicKeyShareG2>,
    rx_vote: Receiver<Vote>,
    tx_cert_handler: Sender<Certificate>,
    processing_vote_aggregators: HashMap<Digest, VotesAggregator>,
}

impl VoteProcessor {
    pub fn spawn(
        committee: Arc<Committee>,
        sorted_keys: Arc<Vec<PublicKeyShareG2>>,
        combined_pubkey: Arc<PublicKeyShareG2>,
        rx_vote: Receiver<Vote>,
        tx_cert_handler: Sender<Certificate>,
    ) {
        tokio::spawn(async move {
            Self {
                committee,
                sorted_keys,
                combined_pubkey,
                rx_vote,
                tx_cert_handler,
                processing_vote_aggregators: HashMap::new(),
            }
            .run()
            .await
            .unwrap();
        });
    }

    async fn run(&mut self) -> DagResult<()> {
        let tx_cert_handler = Arc::new(self.tx_cert_handler.clone());
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
                if let Some(certificate) = vote_aggregator.append(&vote, &self.committee)? {
                    debug!(
                        "Assembled cert {:?} round {}",
                        certificate.header_id, certificate.round
                    );
                    let committee = Arc::clone(&self.committee);
                    let sorted_keys = Arc::clone(&self.sorted_keys);
                    let tx_cert_handler = Arc::clone(&tx_cert_handler);
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
                        let _ = tx_cert_handler.blocking_send(certificate);
                    });
                }
            }
        }
        Ok(())
    }
}
