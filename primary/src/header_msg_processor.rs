use crate::{
    error::{DagError, DagResult},
    messages::Vote,
    primary::{HeaderType, PrimaryMessage},
    synchronizer::Synchronizer,
    Certificate, ConsensusMessage, HeaderInfo, HeaderMessage, Round,
};
use crypto::{BlsSignatureService, Digest, PublicKey};
use dashmap::{DashMap, DashSet};
use log::{debug, info};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

pub struct HeaderMsgProcessor {
    /// The committee information.
    name: PublicKey,
    store: Arc<Store>,
    synchronizer: Synchronizer,
    bls_signature_service: BlsSignatureService,
    tx_certs: Sender<Vec<Certificate>>,
    tx_consensus_header_msg: Sender<ConsensusMessage>,
    // processing_header_infos: DashMap<Digest, HeaderInfo>,
    last_voted: DashMap<Round, DashSet<PublicKey>>,
}

impl HeaderMsgProcessor {
    pub fn new(
        name: PublicKey,
        store: Arc<Store>,
        synchronizer: Synchronizer,
        bls_signature_service: BlsSignatureService,
        tx_certs: Sender<Vec<Certificate>>,
        tx_consensus_header_msg: Sender<ConsensusMessage>,
    ) -> Self {
        Self {
            name,
            store,
            synchronizer,
            bls_signature_service,
            tx_certs,
            tx_consensus_header_msg,
            // processing_header_infos: DashMap::new(),
            last_voted: DashMap::new(),
        }
    }

    pub async fn process_header_msg(
        &self,
        header_msg: &HeaderMessage,
        tx_primary: Arc<Sender<PrimaryMessage>>,
        processing_header_infos: Arc<DashMap<Digest, HeaderInfo>>,
    ) -> DagResult<()> {
        debug!("Processing {:?}", header_msg);
        let header_info: HeaderInfo;

        match header_msg {
            HeaderMessage::HeaderWithCertificate(header_with_parents) => {
                let _ = self
                    .tx_certs
                    .send(header_with_parents.parents.clone())
                    .await;
                // self.process_parent_certificates(&header_with_parents.parents)
                // .await?;
                header_info = HeaderInfo::create_from(&header_with_parents.header);
            }
            HeaderMessage::HeaderInfoWithCertificate(header_info_with_parents) => {
                // self.process_parent_certificates(&header_info_with_parents.parents)
                //     .await?;
                let _ = self
                    .tx_certs
                    .send(header_info_with_parents.parents.clone())
                    .await;
                header_info = header_info_with_parents.header_info.clone();
            }
            HeaderMessage::Header(header) => {
                header_info = HeaderInfo::create_from(&header);
            }
            HeaderMessage::HeaderInfo(h_info) => {
                header_info = h_info.clone();
            }
        }
        info!(
            "received header {:?} round {}",
            header_info.id, header_info.round
        );

        // Indicate that we are processing this header.
        processing_header_infos
            .entry(header_info.id)
            .or_insert(header_info.clone());

        // // Check if we can vote for this header.
        if self
            .last_voted
            .entry(header_info.round)
            .or_insert_with(DashSet::new)
            .insert(header_info.author)
        {
            // Make a vote and send it to all nodes
            let vote =
                Vote::new_for_header_info(&header_info, &self.name, &self.bls_signature_service)
                    .await;
            // debug!("Created {:?}", vote);

            // self.process_vote(&vote, tx_primary)
            //     .await
            //     .expect("Failed to process our own vote");
            let _ = tx_primary.send(PrimaryMessage::MyVote(vote)).await;
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
}
