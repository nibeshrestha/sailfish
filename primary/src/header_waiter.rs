// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::Header;
use crate::primary::{HeaderMessage, HeaderType, PrimaryMessage, Round};
use bytes::Bytes;
use config::Committee;
use crypto::{Digest, PublicKey};
use futures::future::try_join_all;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use log::{debug, error};
use network::SimpleSender;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

/// The resolution of the timer that checks whether we received replies to our sync requests, and triggers
/// new sync requests if we didn't.
const TIMER_RESOLUTION: u64 = 1_000;

/// The commands that can be sent to the `Waiter`.
#[derive(Debug)]
pub enum WaiterMessage {
    // SyncPayload(Digest, Header),
    SyncParents(Vec<Digest>, HeaderType),
}

/// Waits for missing parent certificates and batches' digests.
pub struct HeaderWaiter {
    /// The name of this authority.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,
    /// The delay to wait before re-trying sync requests.
    sync_retry_delay: u64,
    /// Determine with how many nodes to sync when re-trying to send sync-request.
    sync_retry_nodes: usize,

    /// Receives sync commands from the `Synchronizer`.
    rx_synchronizer: Receiver<WaiterMessage>,
    /// Loops back to the core headers for which we got all parents and batches.
    tx_core: Sender<HeaderMessage>,

    /// Network driver allowing to send messages.
    network: SimpleSender,
    /// Keeps the digests of the all certificates for which we sent a sync request,
    /// along with a timestamp (`u128`) indicating when we sent the request.
    parent_requests: HashMap<Digest, (Round, u128)>,
    /// Keeps the digests of the all tx batches for which we sent a sync request,
    /// similarly to `header_requests`.
    // payload_requests: HashMap<Digest, Round>,
    /// List of digests (either certificates, headers or tx batch) that are waiting
    /// to be processed. Their processing will resume when we get all their dependencies.
    pending: HashMap<Digest, (Round, Sender<()>)>,
}

impl HeaderWaiter {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        sync_retry_delay: u64,
        sync_retry_nodes: usize,
        rx_synchronizer: Receiver<WaiterMessage>,
        tx_core: Sender<HeaderMessage>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                consensus_round,
                gc_depth,
                sync_retry_delay,
                sync_retry_nodes,
                rx_synchronizer,
                tx_core,
                network: SimpleSender::new(),
                parent_requests: HashMap::new(),
                // payload_requests: HashMap::new(),
                pending: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    /// Helper function. It waits for particular data to become available in the storage
    /// and then delivers the specified header.
    async fn waiter(
        mut missing: Vec<(Vec<u8>, Store)>,
        deliver: HeaderType,
        mut handler: Receiver<()>,
    ) -> DagResult<Option<HeaderType>> {
        let waiting: Vec<_> = missing
            .iter_mut()
            .map(|(x, y)| y.notify_read(x.to_vec()))
            .collect();
        tokio::select! {
            result = try_join_all(waiting) => {
                result.map(|_| Some(deliver)).map_err(DagError::from)
            }
            _ = handler.recv() => Ok(None),
        }
    }

    /// Main loop listening to the `Synchronizer` messages.
    async fn run(&mut self) {
        let mut waiting = FuturesUnordered::new();

        let timer = sleep(Duration::from_millis(TIMER_RESOLUTION));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                Some(message) = self.rx_synchronizer.recv() => {
                    match message {
                        // WaiterMessage::SyncPayload(missing_header_id, header) => {
                        //     debug!("Synching the payload of {}", header);
                        //     let header_id = header.id.clone();
                        //     let round = header.round;
                        //     let author = header.author;

                        //     // Ensure we sync only once per header.
                        //     if self.pending.contains_key(&header_id) {
                        //         continue;
                        //     }

                        //     // Add the header to the waiter pool. The waiter will return it to when all
                        //     // its parents are in the store.
                        //     let mut wait_for = Vec::new();
                        //     wait_for.push((missing_header_id.to_vec(), self.store.clone()));
                        //     let (tx_cancel, rx_cancel) = channel(1);
                        //     self.pending.insert(header_id, (round, tx_cancel));
                        //     let fut = Self::waiter(wait_for, header, rx_cancel);
                        //     waiting.push(fut);

                        //     // Ensure we didn't already send a sync request for these parents.
                        //     // let mut requires_sync = HashMap::new();

                        //     self.payload_requests.entry(missing_header_id.clone()).or_insert(round);

                        //     let address = self.committee
                        //             .primary(&author)
                        //             .expect("Author of valid header is not in the committee")
                        //             .primary_to_primary;
                        //     let message = PrimaryMessage::PayloadRequest(missing_header_id, author);
                        //     let bytes = bincode::serialize(&message)
                        //         .expect("Failed to serialize batch sync request");
                        //     self.network.send(address, Bytes::from(bytes)).await;

                        // }

                        WaiterMessage::SyncParents(missing, header_type) => {
                            let id : Digest;
                            let round : Round;
                            let author : PublicKey;
                            match header_type.clone() {
                                HeaderType::Header(header) => {
                                    id = header.id.clone();
                                    round = header.round;
                                    author = header.author;
                                }
                                HeaderType::HeaderInfo(header_info) => {
                                    id = header_info.id.clone();
                                    round = header_info.round;
                                    author = header_info.author;
                                }
                            }
                            debug!("Synching the parents of {}", id);


                            // Ensure we sync only once per header.
                            if self.pending.contains_key(&id) {
                                continue;
                            }

                            // Add the header to the waiter pool. The waiter will return it to us
                            // when all its parents are in the store.
                            let wait_for = missing
                                .iter()
                                .cloned()
                                .map(|x| (x.to_vec(), self.store.clone()))
                                .collect();
                            let (tx_cancel, rx_cancel) = channel(1);
                            self.pending.insert(id, (round, tx_cancel));
                            let fut = Self::waiter(wait_for, header_type, rx_cancel);
                            waiting.push(fut);

                            // Ensure we didn't already sent a sync request for these parents.
                            // Optimistically send the sync request to the node that created the certificate.
                            // If this fails (after a timeout), we broadcast the sync request.
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Failed to measure time")
                                .as_millis();
                            let mut requires_sync = Vec::new();
                            for missing in missing {
                                self.parent_requests.entry(missing.clone()).or_insert_with(|| {
                                    requires_sync.push(missing);
                                    (round, now)
                                });
                            }
                            if !requires_sync.is_empty() {
                                let address = self.committee
                                    .primary(&author)
                                    .expect("Author of valid header not in the committee")
                                    .primary_to_primary;
                                let message = PrimaryMessage::CertificatesRequest(requires_sync, self.name);
                                let bytes = bincode::serialize(&message).expect("Failed to serialize cert request");
                                self.network.send(address, Bytes::from(bytes)).await;
                            }
                        }
                    }
                },

                Some(result) = waiting.next() => match result {
                    Ok(Some(header_type)) => {
                        let id : Digest;
                        let parents : Vec<_>;
                        match header_type.clone() {
                            HeaderType::Header(header) => {
                                id = header.id;
                                parents = header.parents.clone();
                                let _ = self.pending.remove(&id);
                          
                                for x in &parents {
                                    let _ = self.parent_requests.remove(&x);
                                }
                                self.tx_core.send(HeaderMessage::Header(header)).await.expect("Failed to send header");
                            }
                            HeaderType::HeaderInfo(header_info) => {
                                id = header_info.id;
                                parents = header_info.parents.clone();
                                let _ = self.pending.remove(&id);
                            
                                for x in &parents {
                                    let _ = self.parent_requests.remove(&x);
                                }
                                self.tx_core.send(HeaderMessage::HeaderInfo(header_info)).await.expect("Failed to send header");
                            }
                        }
                        
                    },
                    Ok(None) => {
                        // This request has been canceled.
                    },
                    Err(e) => {
                        error!("{}", e);
                        panic!("Storage failure: killing node.");
                    }
                },

                () = &mut timer => {
                    // We optimistically sent sync requests to a single node. If this timer triggers,
                    // it means we were wrong to trust it. We are done waiting for a reply and we now
                    // broadcast the request to all nodes.
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Failed to measure time")
                        .as_millis();

                    let mut retry = Vec::new();
                    for (digest, (_, timestamp)) in &self.parent_requests {
                        if timestamp + (self.sync_retry_delay as u128) < now {
                            debug!("Requesting sync for certificate {} (retry)", digest);
                            retry.push(digest.clone());
                        }
                    }

                    let addresses = self.committee
                        .others_primaries(&self.name)
                        .iter()
                        .map(|(_, x)| x.primary_to_primary)
                        .collect();
                    let message = PrimaryMessage::CertificatesRequest(retry, self.name);
                    let bytes = bincode::serialize(&message).expect("Failed to serialize cert request");
                    self.network.lucky_broadcast(addresses, Bytes::from(bytes), self.sync_retry_nodes).await;

                    // Reschedule the timer.
                    timer.as_mut().reset(Instant::now() + Duration::from_millis(TIMER_RESOLUTION));
                }
            }

            // Cleanup internal state.
            let round = self.consensus_round.load(Ordering::Relaxed);
            if round > self.gc_depth {
                let mut gc_round = round - self.gc_depth;

                for (r, handler) in self.pending.values() {
                    if r <= &gc_round {
                        let _ = handler.send(()).await;
                    }
                }
                self.pending.retain(|_, (r, _)| r > &mut gc_round);
                // self.payload_requests.retain(|_, r| r > &mut gc_round);
                self.parent_requests.retain(|_, (r, _)| r > &mut gc_round);
            }
        }
    }
}
