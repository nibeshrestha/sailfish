use async_trait::async_trait;
use bytes::Bytes;
use config::{Committee, Parameters, WorkerId};
use crypto::{Digest, PublicKey};
use log::info;
use network::{MessageHandler, Receiver, Writer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::sync::mpsc::{channel, Sender};

pub type Transaction = Vec<u8>;
pub type Batch = Vec<Transaction>;

// #[cfg(test)]
// #[path = "tests/worker_tests.rs"]
// pub mod worker_tests;

/// The default channel capacity for each channel of the worker.
pub const CHANNEL_CAPACITY: usize = 1_000;

/// The primary round number.
// TODO: Move to the primary.
pub type Round = u64;

/// The message exchanged between workers.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerMessage {
    Batch(Batch),
    BatchRequest(Vec<Digest>, /* origin */ PublicKey),
}

pub struct Worker {
    /// The public key of this authority.
    name: PublicKey,
    /// The id of this worker.
    id: WorkerId,
    /// The committee information.
    committee: Committee,
    /// The configuration parameters.
    parameters: Parameters,
    tx_txns: Sender<Transaction>,
}

impl Worker {
    pub fn spawn(
        name: PublicKey,
        id: WorkerId,
        committee: Committee,
        parameters: Parameters,
        tx_txns: Sender<Transaction>,
    ) {
        // Define a worker instance.
        let worker = Self {
            name,
            id,
            committee,
            parameters,
            tx_txns,
        };

        // Spawn all worker tasks.
        // let (tx_primary, rx_primary) = channel(CHANNEL_CAPACITY);
        worker.handle_clients_transactions();

        // NOTE: This log entry is used to compute performance.
        info!(
            "Worker {} successfully booted on {}",
            id,
            worker
                .committee
                .worker(&worker.name, &worker.id)
                .expect("Our public key or worker id is not in the committee")
                .transactions
                .ip()
        );
    }

    /// Spawn all tasks responsible to handle clients transactions.
    fn handle_clients_transactions(&self) {
        let tx_txns = self.tx_txns.clone();
        // We first receive clients' transactions from the network.
        let mut address = self
            .committee
            .worker(&self.name, &self.id)
            .expect("Our public key or worker id is not in the committee")
            .transactions;
        address.set_ip("0.0.0.0".parse().unwrap());
        Receiver::spawn(address, /* handler */ TxReceiverHandler { tx_txns });

        // The transactions are sent to the `BatchMaker` that assembles them into batches. It then broadcasts
        // (in a reliable manner) the batches to all other workers that share the same `id` as us. Finally, it
        // gathers the 'cancel handlers' of the messages and send them to the `QuorumWaiter`.
        // BatchMaker::spawn(
        //     self.parameters.batch_size,
        //     self.parameters.max_batch_delay,
        //     /* rx_transaction */ rx_batch_maker,
        //     self.tx_txns.clone(),
        // );

        info!(
            "Worker {} listening to client transactions on {}",
            self.id, address
        );
    }
}

/// Defines how the network receiver handles incoming transactions.
#[derive(Clone)]
struct TxReceiverHandler {
    tx_txns: Sender<Transaction>,
}

#[async_trait]
impl MessageHandler for TxReceiverHandler {
    async fn dispatch(&self, _writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        // Send the transaction to the batch maker.
        self.tx_txns
            .send(message.to_vec())
            .await
            .expect("Failed to send transaction");

        // Give the change to schedule other tasks.
        tokio::task::yield_now().await;
        Ok(())
    }
}
