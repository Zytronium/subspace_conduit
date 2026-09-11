use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};

// -------- self-signed cert generation (unchanged from before) --------
fn generate_self_signed_cert() -> anyhow::Result<rcgen::CertifiedKey> {
    Ok(rcgen::generate_simple_self_signed(vec!["subspace-conduit.local".to_string()])?)
}

fn identity_paths() -> anyhow::Result<(PathBuf, PathBuf)> {
    let mut dir = dirs::config_dir().ok_or_else(|| anyhow::anyhow!("could not determine config directory"))?;
    dir.push("subspace_conduit");
    std::fs::create_dir_all(&dir)?;
    Ok((dir.join("server_cert.pem"), dir.join("server_key.pem")))
}

fn load_or_generate_identity() -> anyhow::Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
    let (cert_path, key_path) = identity_paths()?;
    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read(&cert_path)?;
        let key_pem = std::fs::read(&key_path)?;
        let cert = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_slice()))
            .next().ok_or_else(|| anyhow::anyhow!("no certificate found"))??;
        let key = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(key_pem.as_slice()))
            .next().ok_or_else(|| anyhow::anyhow!("no private key found"))??;
        return Ok((cert, PrivatePkcs8KeyDer::from(key.secret_pkcs8_der().to_vec())));
    }
    let certified_key = generate_self_signed_cert()?;
    std::fs::write(&cert_path, certified_key.cert.pem())?;
    std::fs::write(&key_path, certified_key.key_pair.serialize_pem())?;
    let cert_der = certified_key.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(certified_key.key_pair.serialize_der());
    Ok((cert_der, key_der))
}

pub fn build_server_config() -> anyhow::Result<Arc<ServerConfig>> {
    let (cert, key) = load_or_generate_identity()?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], PrivateKeyDer::from(key))?;
    Ok(Arc::new(config))
}

// -------- peek verifier: accepts any cert, used only to capture a fingerprint --------
#[derive(Debug)]
struct PeekVerifier;

impl ServerCertVerifier for PeekVerifier {
    fn verify_server_cert(&self, _e: &CertificateDer<'_>, _i: &[CertificateDer<'_>], _s: &ServerName<'_>, _o: &[u8], _n: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _m: &[u8], _c: &CertificateDer<'_>, _d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _m: &[u8], _c: &CertificateDer<'_>, _d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::RSA_PKCS1_SHA256, SignatureScheme::ECDSA_NISTP256_SHA256, SignatureScheme::ED25519]
    }
}

pub fn build_peek_client_config() -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PeekVerifier))
            .with_no_client_auth(),
    )
}

// -------- strict verifier: only succeeds against an already-known, matching fingerprint --------
#[derive(Debug)]
struct StrictVerifier {
    store: Arc<crate::trust::KnownHostsStore>,
}

impl ServerCertVerifier for StrictVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _i: &[CertificateDer<'_>], server_name: &ServerName<'_>, _o: &[u8], _n: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(end_entity.as_ref()));
        let host_key = format!("{server_name:?}");
        match self.store.known_fingerprint(&host_key) {
            Some(known) if known == fingerprint => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General("fingerprint mismatch, trust was revoked or server changed".into())),
            None => Err(rustls::Error::General("server not yet trusted, probe and confirm first".into())),
        }
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

pub fn build_strict_client_config(store: Arc<crate::trust::KnownHostsStore>) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(StrictVerifier { store }))
            .with_no_client_auth(),
    )
}
