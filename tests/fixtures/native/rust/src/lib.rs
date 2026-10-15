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
}
