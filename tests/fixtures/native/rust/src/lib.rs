//! Intentionally flawed toy state machine for native workflow smoke tests.

#[derive(Default)]
pub struct Ledger {
    pub unsafe_credit: u64,
    pub safe_credit: u64,
}

impl Ledger {
    pub fn issue(&mut self, amount: u64) {
        self.unsafe_credit += amount;
        self.safe_credit += amount;
    }
    pub fn unsafe_claim(&mut self, amount: u64) -> bool {
        self.unsafe_credit >= amount
    }
    pub fn safe_claim(&mut self, amount: u64) -> bool {
        if self.safe_credit < amount {
            return false;
        }
        self.safe_credit -= amount;
        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use super::Ledger;

    #[test]
    fn test_candidate_replay() {
        let mut ledger = Ledger::default();
        ledger.issue(10);
        assert!(ledger.unsafe_claim(10));
        assert!(ledger.unsafe_claim(10));
        assert_eq!(ledger.unsafe_credit, 10);
    }

    #[test]
    fn test_negative_control() {
        let mut ledger = Ledger::default();
        ledger.issue(10);
        assert!(ledger.safe_claim(10));
        assert!(!ledger.safe_claim(10));
    }

    #[test]
    fn test_candidate_duplicate_signer_quorum() {
        let authorized = HashSet::from(["alice", "bob"]);
        let authenticated = ["alice", "alice"];
        let raw_count = authenticated.len();
        let unique_authorized = authenticated.iter().copied()
            .filter(|signer| authorized.contains(signer))
            .collect::<HashSet<_>>().len();
        assert_eq!(raw_count, 2);
        assert_eq!(unique_authorized, 1);
        assert!(raw_count >= 2 && unique_authorized < 2);
    }

    #[test]
    fn test_negative_control_unique_signer_quorum() {
        let authorized = HashSet::from(["alice", "bob"]);
        let authenticated = ["alice", "bob"];
        let unique_authorized = authenticated.iter().copied()
            .filter(|signer| authorized.contains(signer))
            .collect::<HashSet<_>>().len();
        assert_eq!(unique_authorized, 2);
        assert!(unique_authorized >= 2);
    }
}
