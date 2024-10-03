use crate::aggregators::CertificatesAggregator;
use crate::error::DagResult;
use crate::messages::Certificate;
use crate::primary::Round;
use async_recursion::async_recursion;
use config::Committee;
use crypto::PublicKey;
use log::{debug, info, warn};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc::{Receiver, Sender};
pub struct CertificateHandler {
    certificates_aggregators: HashMap<Round, Box<CertificatesAggregator>>,
    rx_certificate: Receiver<Certificate>,
    rx_certs: Receiver<Vec<Certificate>>,
    tx_consensus: Sender<Certificate>,
    tx_proposer: Sender<(Vec<Certificate>, Round)>,
    processed_certs: HashMap<Round, HashSet<PublicKey>>,
    leaders_per_round: usize,
    committee: Committee,
    consensus_round: Arc<AtomicU64>,
    /// The last garbage collected round.
    gc_round: Round,
    gc_depth: Round,
}
impl CertificateHandler {
    pub fn spawn(
        rx_certificate: Receiver<Certificate>,
        rx_certs: Receiver<Vec<Certificate>>,
        tx_consensus: Sender<Certificate>,
        tx_proposer: Sender<(Vec<Certificate>, Round)>,
        leaders_per_round: usize,
        gc_depth: Round,
        committee: Committee,
        consensus_round: Arc<AtomicU64>,
    ) {
        tokio::spawn(async move {
            Self {
                rx_certificate,
                rx_certs,
                certificates_aggregators: HashMap::with_capacity(2 * gc_depth as usize),
                tx_consensus,
                tx_proposer,
                processed_certs: HashMap::with_capacity(2 * gc_depth as usize),
                leaders_per_round,
                committee,
                consensus_round,
                gc_round: 0,
                gc_depth,
            }
            .run()
            .await
            .unwrap();
        });
    }
    #[async_recursion]
    async fn process_certificate(&mut self, certificate: Certificate) -> DagResult<()> {
        debug!(
            "Processing cert {:?} round {}",
            certificate.header_id, certificate.round
        );
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
    async fn run(&mut self) -> DagResult<()> {
        loop {
            let _ = tokio::select! {
                Some(certificate) = self.rx_certificate.recv() => self.process_certificate(certificate).await,
                Some(certs) = self.rx_certs.recv() => {
                    for cert in certs {
                        let _ = self.process_certificate(cert).await;
                    }
                    Ok(())
                }
                // Some(certificate) = self.rx_certificate_waiter.recv() => self.process_certificate(certificate).await,
            };
            // Cleanup internal state.
            let round = self.consensus_round.load(Ordering::Relaxed);
            if round > self.gc_depth {
                let gc_round = round - self.gc_depth;
                self.certificates_aggregators.retain(|k, _| k >= &gc_round);
                self.gc_round = gc_round;
            }
        }
    }
}
