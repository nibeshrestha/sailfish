// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, Timeout, TimeoutCert, Vote, NoVoteMsg, NoVoteCert};
use config::{Committee, Stake};
use crypto::{PublicKey, Signature};
use log::debug;
use std::collections::HashSet;

/// Aggregates votes for a particular header into a certificate.
pub struct VotesAggregator {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl VotesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        vote: Vote,
        committee: &Committee,
        header: &Header,
    ) -> DagResult<Option<Certificate>> {
        let author = vote.author;

        // Ensure it is the first time this authority votes.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.votes.push((author, vote.signature));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(Certificate {
                header: header.clone(),
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}

/// Aggregate certificates and check if we reach a quorum.
pub struct CertificatesAggregator {
    weight: Stake,
    certificates: Vec<Certificate>,
    used: HashSet<PublicKey>,
}

impl CertificatesAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            certificates: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        certificate: Certificate,
        committee: &Committee,
    ) -> DagResult<Option<Vec<Certificate>>> {
        let origin = certificate.origin();

        // Ensure it is the first time this authority votes.
        if !self.used.insert(origin) {
            return Ok(None);
        }

        self.certificates.push(certificate.clone());
        self.weight += committee.stake(&origin);

        let leaders = committee.leader_list(2, certificate.round() as usize);
        for leader in leaders.iter() {
            if !self.used.contains(leader){
                return Ok(None);
            }
        }
        debug!("Got all leader for round {}", certificate.round());
        if self.weight >= committee.quorum_threshold() {
            //self.weight = 0; // Ensures quorum is only reached once.
            return Ok(Some(self.certificates.drain(..).collect()));
        }
        Ok(None)
    }
}

/// Aggregates timeouts for a particular round into an action or trigger.
pub struct TimeoutAggregator {
    weight: Stake,
    timeouts: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl TimeoutAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            timeouts: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        timeout: Timeout,
        committee: &Committee,
    ) -> DagResult<Option<TimeoutCert>> {
        let author = timeout.author;

        // Ensure it is the first time this authority sends a timeout.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.timeouts.push((author, timeout.signature));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            // Once quorum is reached, you might want to reset for the next round or trigger an action.
            return Ok(Some(TimeoutCert {
                round: timeout.round.clone(),
                timeouts: self.timeouts.clone(),
            })); // Return the authorities that contributed to this quorum.
        }
        Ok(None)
    }
}

/// Aggregates no-vote messages for a particular round into a certification.
pub struct NoVoteAggregator {
    weight: Stake,
    no_votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
}

impl NoVoteAggregator {
    pub fn new() -> Self {
        Self {
            weight: 0,
            no_votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    pub fn append(
        &mut self,
        no_vote_msg: NoVoteMsg,
        committee: &Committee,
    ) -> DagResult<Option<NoVoteCert>> {
        let author = no_vote_msg.author;

        // Ensure it is the first time this authority sends a no-vote message.
        ensure!(self.used.insert(author), DagError::AuthorityReuse(author));

        self.no_votes.push((author, no_vote_msg.signature));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            // Once quorum is reached, you might reset for the next round or use the certification as needed.
            return Ok(Some(NoVoteCert {
                round: no_vote_msg.round.clone(),
                no_votes: self.no_votes.clone(),
            })); // Return the certification that aggregates the no-votes reaching quorum.
        }
        Ok(None)
    }
}
