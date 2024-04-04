use rustls::{
    sign::{any_supported_type, CertifiedKey},
    Certificate as RustlsCertificate, PrivateKey,
};
use std::sync::Arc;
use x509_cert::der::Encode;
use x509_cert::Certificate; // Use the alias from x509-cert

pub const MY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
use cms::builder::SignedDataBuilder;
use cms::cert::CertificateChoices;
use cms::signed_data::EncapsulatedContentInfo;
use const_oid::ObjectIdentifier;

/// Configuration for package signing.
pub struct SignConfig {
    pub cert: Certificate,      // Adjusted to use Certificate from x509-cert
    pub sign_cert: Certificate, // Adjusted to use Certificate from x509-cert
    pub sign_key: Arc<CertifiedKey>,
}

impl SignConfig {
    pub fn new(
        wwdr: WWDR,
        sign_cert_bytes: &[u8],
        sign_key_bytes: &[u8],
    ) -> Result<SignConfig, Box<dyn std::error::Error>> {
        // Use load_pem_chain for loading the certificate chain
        let cert = match wwdr {
            WWDR::G4 => Certificate::load_pem_chain(G4_CERT)?
                .pop()
                .ok_or("No G4 certificate found")?,
            WWDR::Custom(buf) => Certificate::load_pem_chain(buf)?
                .pop()
                .ok_or("No custom certificate found")?,
        };

        let sign_certs = Certificate::load_pem_chain(sign_cert_bytes)?;
        let sign_cert = sign_certs
            .into_iter()
            .next()
            .ok_or("No sign certificate found")?;

        // Use the raw PKCS#8 bytes for PrivateKey as before
        let private_key = PrivateKey(sign_key_bytes.to_vec());
        let signing_key =
            any_supported_type(&private_key).map_err(|_| "Unsupported private key type")?;

        // Convert sign_cert into rustls's Certificate format for CertifiedKey
        let rustls_sign_cert = RustlsCertificate(sign_cert.to_der()?); // Assuming .to_der() method or similar functionality exists

        // Construct CertifiedKey without double wrapping in Arc
        let certified_key = CertifiedKey::new(vec![rustls_sign_cert], signing_key);

        Ok(SignConfig {
            cert,
            sign_cert,
            sign_key: Arc::new(certified_key),
        })
    }

    pub fn generate_p7b(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // EncapsulatedContentInfo might need to be adjusted based on your specific requirements
        let encap_content_info = EncapsulatedContentInfo {
            econtent_type: MY_OID,
            econtent: None,
        };

        let mut builder = SignedDataBuilder::new(&encap_content_info);

        // Convert your certificates to CertificateChoices, if necessary
        let cert_choice = CertificateChoices::from(cms::cert::CertificateChoices::Certificate(
            self.cert.clone(),
        )); // Adjust as necessary
        let sign_cert_choice = CertificateChoices::from(
            cms::cert::CertificateChoices::Certificate(self.sign_cert.clone()),
        ); // Adjust as necessary

        // Add certificates to the builder
        builder.add_certificate(cert_choice).unwrap();
        builder.add_certificate(sign_cert_choice).unwrap();

        // Build the SignedData structure
        let signed_data = builder.build().unwrap();

        // Serialize to DER
        let der_bytes = signed_data.to_der().unwrap();

        Ok(der_bytes)
    }
}

const G4_CERT: &[u8; 1113] = include_bytes!("AppleWWDRCAG4.cer");

pub enum WWDR<'a> {
    G4,
    Custom(&'a [u8]),
}
