//! Ephemeral CA certificate generation using rcgen

use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

pub struct EphemeralCA {
    pub cert_pem: String,
    pub key_pem: String,
}

impl EphemeralCA {
    /// Generate a new ephemeral root CA certificate.
    ///
    /// The certificate is valid for 24 hours and is regenerated each session.
    pub fn generate() -> anyhow::Result<Self> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Phoenix Firewall Ephemeral CA");
        dn.push(DnType::OrganizationName, "Phoenix Security");
        params.distinguished_name = dn;

        // Valid for 24 hours (ephemeral — regenerated each session)
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(24);

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;

        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        })
    }
}
