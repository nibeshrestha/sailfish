// Copyright(C) Facebook, Inc. and its affiliates.
use crate::{
    primary::{HeaderMessage, HeaderType, PrimaryMessage},
    HeaderInfo,
};
use bytes::Bytes;
use config::{Clan, Committee};
use crypto::{Digest, PublicKey};
use log::{error, warn};
use network::SimpleSender;
use store::Store;
use tokio::sync::mpsc::Receiver;

/// A task dedicated to help other authorities by replying to their certificates requests.
pub struct Helper {
    /// The committee information.
    committee: Committee,
    clan: Clan,
    /// The persistent storage.
    store: Store,
    /// Input channel to receive certificates requests.
    rx_primaries: Receiver<(Vec<Digest>, PublicKey)>,
    /// A network sender to reply to the sync requests.
    network: SimpleSender,
}

impl Helper {
    pub fn spawn(
        committee: Committee,
        clan: Clan,
        store: Store,
        rx_primaries: Receiver<(Vec<Digest>, PublicKey)>,
    ) {
        tokio::spawn(async move {
            Self {
                committee,
                clan,
                store,
                rx_primaries,
                network: SimpleSender::new(),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        while let Some((digests, origin)) = self.rx_primaries.recv().await {
            // TODO [issue #195]: Do some accounting to prevent bad nodes from monopolizing our resources.

            // get the requestors address.
            let address = match self.committee.primary(&origin) {
                Ok(x) => x.primary_to_primary,
                Err(e) => {
                    warn!("Unexpected certificate request: {}", e);
                    continue;
                }
            };

            // Reply to the request (the best we can).
            for digest in digests {
                match self.store.read(digest.to_vec()).await {
                    Ok(Some(data)) => {
                        // TODO: Remove this deserialization-serialization in the critical path.
                        let header_msg = bincode::deserialize(&data).unwrap();

                        if let HeaderType::Header(header) = header_msg {
                            if self.clan.is_member(&origin) {
                                let bytes = bincode::serialize(&PrimaryMessage::HeaderMsg(
                                    HeaderMessage::Header(header),
                                ))
                                .expect("Failed to serialize our own certificate");
                                self.network.send(address, Bytes::from(bytes)).await;
                            } else {
                                let header_info = HeaderInfo::create_from(&header);
                                let bytes = bincode::serialize(&PrimaryMessage::HeaderMsg(
                                    HeaderMessage::HeaderInfo(header_info),
                                ))
                                .expect("Failed to serialize our own certificate");
                                self.network.send(address, Bytes::from(bytes)).await;
                            }
                        }
                    }
                    Ok(None) => (),
                    Err(e) => error!("{}", e),
                }
            }
        }
    }
}
