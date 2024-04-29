# Multi-leader Sailfish

This repo provides an implementation of Multi-leader Sailfish. The core consensus logic of Bullshark is modified to obtain Sailfish. The codebase has been designed to be small, efficient, and easy to benchmark and modify. It has not been designed to run in production but uses real cryptography ([dalek](https://doc.dalek.rs/ed25519_dalek)), networking ([tokio](https://docs.rs/tokio)), and storage ([rocksdb](https://docs.rs/rocksdb)).
