//! Deterministic attribute minimization with an explicit, one-time user
//! authorization decision. No AI, implicit grants, or external runtime.

use aitanti_vault::{Date, Profile, VaultError};
use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribute {
    AgeOver18,
    ShippingAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDecision {
    Deny,
    ApproveOnce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureRequest {
    pub service: String,
    pub purpose: String,
    pub attribute: Attribute,
}

impl DisclosureRequest {
    pub fn new(
        service: &str,
        purpose: &str,
        attribute: Attribute,
    ) -> Result<Self, DisclosureError> {
        if service.is_empty() || purpose.is_empty() {
            return Err(DisclosureError::InvalidRequest);
        }
        Ok(Self {
            service: service.to_owned(),
            purpose: purpose.to_owned(),
            attribute,
        })
    }
}

/// Deliberately no `Debug`: it can contain an actual personal address.
#[derive(PartialEq, Eq)]
pub enum ReleasedAttribute {
    /// Self-assertion, NOT independently cryptographically verifiable.
    AgeOver18(bool),
    ShippingAddress(String),
}

#[derive(Debug)]
pub enum DisclosureError {
    InvalidRequest,
    InvalidDate(VaultError),
}

impl fmt::Display for DisclosureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => write!(f, "invalid disclosure request"),
            Self::InvalidDate(_) => write!(f, "invalid date for attribute check"),
        }
    }
}
impl Error for DisclosureError {}

/// Always default-deny. A caller must supply a fresh and explicit
/// `ApproveOnce` result from its local approval interaction.
pub fn disclose(
    profile: &Profile,
    request: &DisclosureRequest,
    decision: UserDecision,
    today: Date,
) -> Result<Option<ReleasedAttribute>, DisclosureError> {
    if decision == UserDecision::Deny {
        return Ok(None);
    }
    let value = match request.attribute {
        Attribute::AgeOver18 => ReleasedAttribute::AgeOver18(
            profile
                .age_over_18(today)
                .map_err(DisclosureError::InvalidDate)?,
        ),
        Attribute::ShippingAddress => {
            ReleasedAttribute::ShippingAddress(profile.shipping_address.clone())
        }
    };
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipping_address_is_never_released_without_approval() {
        let profile = Profile::fictitious();
        let request = DisclosureRequest::new(
            "service-b.local",
            "deliver order",
            Attribute::ShippingAddress,
        )
        .expect("request");
        let now = Date::new(2026, 10, 8).expect("date");
        assert!(
            disclose(&profile, &request, UserDecision::Deny, now)
                .expect("decision")
                .is_none()
        );
        let value = disclose(&profile, &request, UserDecision::ApproveOnce, now).expect("decision");
        assert!(matches!(value, Some(ReleasedAttribute::ShippingAddress(_))));
    }

    #[test]
    fn age_assertion_does_not_release_birth_date() {
        let request = DisclosureRequest::new("service-a.local", "age check", Attribute::AgeOver18)
            .expect("request");
        let now = Date::new(2026, 10, 8).expect("date");
        let value = disclose(
            &Profile::fictitious(),
            &request,
            UserDecision::ApproveOnce,
            now,
        )
        .expect("decision");
        assert!(matches!(value, Some(ReleasedAttribute::AgeOver18(true))));
    }
}
