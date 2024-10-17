use std::{collections::{HashMap, HashSet}, sync::{Arc, RwLock}};

use crate::{
    error::{DagError, DagResult}, messages::Vote, primary::{HeaderType, PrimaryMessage}, synchronizer::Synchronizer, Certificate, ConsensusMessage, HeaderInfo, HeaderMessage, Round
};
use blsttc::PublicKeyShareG2;
use config::{Clan, Committee};
use crypto::{BlsSignatureService, Digest, PublicKey};
use log::{debug, info};
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

pub struct HeaderMsgProcessor {
    /// The committee information.
    name : PublicKey,
    committee: Arc<Committee>,
    clan: Arc<Clan>,
    sorted_keys: Arc<Vec<PublicKeyShareG2>>,
    combined_pubkey: Arc<PublicKeyShareG2>,
    store: Arc<Store>,
    synchronizer: Synchronizer,
    bls_signature_service: BlsSignatureService,
    tx_certs : Sender<Vec<Certificate>>,
    tx_consensus_header_msg: Sender<ConsensusMessage>,
    // processing_vote_aggregators: HashMap<Digest, VotesAggregator>,
}

impl HeaderMsgProcessor {
    pub fn new(
        name: PublicKey,
        committee: Arc<Committee>,
        clan: Arc<Clan>,
        sorted_keys: Arc<Vec<PublicKeyShareG2>>,
        combined_pubkey: Arc<PublicKeyShareG2>,
        store: Arc<Store>,
        synchronizer: Synchronizer,
        bls_signature_service: BlsSignatureService,
        tx_certs : Sender<Vec<Certificate>>,
        tx_consensus_header_msg: Sender<ConsensusMessage>,
    ) -> Self{
        
            Self {
                name,
                committee,
                clan,
                sorted_keys,
                combined_pubkey,
                store,
                synchronizer,
                bls_signature_service,
                tx_certs,
                tx_consensus_header_msg,
            }
    }

    pub async fn process_header_msg(&self,  header_msg: &HeaderMessage, tx_primary: Arc<Sender<PrimaryMessage>>, processing_header_infos: Arc<RwLock<HashMap<Digest, HeaderInfo>>>, last_voted: Arc<RwLock<HashMap<Round, HashSet<PublicKey>>>>) -> DagResult<()> {
        
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
        processing_header_infos.write().unwrap().entry(header_info.id)
            .or_insert(header_info.clone());

        // // Check if we can vote for this header.
        if last_voted.write().unwrap()
            .entry(header_info.round)
            .or_insert_with(HashSet::new)
            .insert(header_info.author)
        {
            // Make a vote and send it to all nodes
            let vote = Vote::new_for_header_info(
                &header_info,
                &self.name,
                &self.bls_signature_service,
            )
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
