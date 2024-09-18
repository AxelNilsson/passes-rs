use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use sha1::Sha1;
use spki::der::Decode;
use spki::der::DecodePem;
use x509_cert::Certificate;

/// Configuration for package signing.
///
/// Contains WWDR (Apple Worldwide Developer Relations), Signer Certificate (Developer), Signer Certificate Key (Developer)
/// certificate for pass signing with private key
pub struct SignConfig {
    pub cert: Certificate,
    pub sign_cert: Certificate,
    pub sign_key: SigningKey<Sha1>,
}

impl SignConfig {
    /// Create new config from buffers
    pub fn new(
        wwdr: WWDR,
        sign_cert: &[u8],
        sign_key: &[u8],
    ) -> Result<SignConfig, Box<dyn std::error::Error>> {
        let cert = match wwdr {
            WWDR::G4 => Certificate::from_der(G4_CERT)?,
            WWDR::Custom(buf) => Certificate::from_pem(buf)?,
        };

        let sign_cert = Certificate::from_pem(sign_cert)?;

        let rsa_private_key = if sign_key.starts_with(b"-----BEGIN RSA PRIVATE KEY-----") {
            // PKCS#1 PEM format
            RsaPrivateKey::from_pkcs1_pem(std::str::from_utf8(sign_key)?)?
        } else if sign_key.starts_with(b"-----BEGIN PRIVATE KEY-----") {
            // PKCS#8 PEM format
            RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(sign_key)?)?
        } else {
            // Assume DER format (could be PKCS#1 or PKCS#8)
            RsaPrivateKey::from_pkcs1_der(sign_key)
                .or_else(|_| RsaPrivateKey::from_pkcs8_der(sign_key))?
        };

        let sign_key = SigningKey::<Sha1>::new(rsa_private_key);

        Ok(SignConfig {
            cert,
            sign_cert,
            sign_key,
        })
    }
}

/// G4 certificate from https://www.apple.com/certificateauthority/
const G4_CERT: &[u8; 1113] = include_bytes!("AppleWWDRCAG4.cer");

/// Predefined certificate from Apple CA, or custom certificate
pub enum WWDR<'a> {
    G4,
    Custom(&'a [u8]),
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePrivateKey;

    /// Make x509 certificate and private key
    fn make_cert() -> Result<(Certificate, SigningKey<Sha1>), Error> {
        // This is a simplified version. You'll need to implement proper certificate generation.
        let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let signing_key = SigningKey::<Sha1>::new(private_key);

        // Create a self-signed certificate (this is a placeholder)
        let cert = Certificate::self_signed(
            &signing_key,
            "CN=Test",
            &x509_cert::time::Duration::days(365),
        )
        .unwrap();

        Ok((cert, signing_key))
    }

    #[test]
    fn create_config() {
        // Generate certificate
        let (sign_cert, sign_key) = make_cert().unwrap();

        let sign_cert = sign_cert.to_pem().unwrap();
        let sign_key = sign_key.to_pkcs8_pem().unwrap();

        let _ = SignConfig::new(WWDR::G4, sign_cert.as_bytes(), sign_key.as_bytes()).unwrap();
    }
}
