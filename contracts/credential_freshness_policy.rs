// StellarCred: Credential Freshness Policy (Issue #556)
pub struct CredentialVerificationPolicy {
    pub max_age_seconds: u64,
}

impl CredentialVerificationPolicy {
    pub fn verify_freshness(&self, issued_at: u64, current_time: u64) -> Result<(), &'static str> {
        if current_time < issued_at {
            return Err("Credential issuance timestamp is in the future");
        }
        if current_time - issued_at > self.max_age_seconds {
            return Err("Credential exceeds maximum allowable age for protocol");
        }
        Ok(())
    }
}
