use std::io::{self, Write};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use subspace_conduit_core::trust::KnownHostsStore;
use tracing::{info, warn};

// -------- interactive trust on first use verifier --------
#[derive(Debug)]
pub struct TofuVerifier {
    store: Arc<KnownHostsStore>,
    host_key: String,
}

impl TofuVerifier {
    pub fn new(store: Arc<KnownHostsStore>, host_key: String) -> Self {
        Self { store, host_key }
    }
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = hex::encode(Sha256::digest(end_entity.as_ref()));
        match self.store.known_fingerprint(&self.host_key) {
            Some(known) if known == fingerprint => Ok(ServerCertVerified::assertion()),
            Some(known) => {
                let reason = format!(
                    "fingerprint mismatch for {}: expected {known}, got {fingerprint}. \
                     This could mean the server changed, or a man-in-the-middle attack."
                    , self.host_key
                );
                warn!("{reason}");
                Err(rustls::Error::General(reason))
            }
            None => {
                if prompt_confirm(&self.host_key, &fingerprint) {
                    if let Err(e) = self.store.trust(&self.host_key, &fingerprint) {
                        let reason = format!("failed to save trust decision: {e}");
                        warn!("{reason}");
                        return Err(rustls::Error::General(reason));
                    }
                    info!("trusted server {} with fingerprint {fingerprint}", self.host_key);
                    Ok(ServerCertVerified::assertion())
                } else {
                    let reason = format!(
                        "user declined to trust new server {} with fingerprint {fingerprint}", self.host_key
                    );
                    warn!("{reason}");
                    Err(rustls::Error::General(reason))
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// -------- interactive prompt --------
fn prompt_confirm(host_key: &str, fingerprint: &str) -> bool {
    println!();
    println!("The authenticity of server '{host_key}' can't be established.");
    println!("Certificate fingerprint (SHA256): {fingerprint}");
    println!("Verify this fingerprint matches what the server shows, out of band,");
    println!("before continuing (e.g. read aloud in person, sent via a trusted channel).");
    print!("Trust this server and continue connecting? [y/N] ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

pub fn build_client_config(store: Arc<KnownHostsStore>, host_key: String) -> Arc<ClientConfig> {
    let verifier = TofuVerifier::new(store, host_key);
    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth(),
    )
}
