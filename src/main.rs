mod pb;
mod server;
mod settings;
mod stripe;
mod webhook_server;

use crate::server::PaymentProcessorService;
use anyhow::Result;
use std::{fs, net::SocketAddr, path::Path};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic_reflection::server::Builder as ReflectionBuilder;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    // Load configuration from environment
    let cfg = settings::Config::from_env();

    // Validate Stripe configuration
    if cfg.stripe.api_key.is_empty() {
        tracing::error!("STRIPE_API_KEY not set; exiting");
        return Ok(());
    }
    tracing::info!("Starting Stripe payment processor");

    let addr: SocketAddr = format!("0.0.0.0:{}", cfg.server_port).parse()?;
    
    let svc = PaymentProcessorService::try_new(cfg.clone()).await?;
    
    // Start webhook HTTP server in background if webhook secret is configured
    if !cfg.stripe.webhook_secret.is_empty() {
        let webhook_port = cfg.server_port + 1; // Use next port for webhooks
        let payment_state = svc.stripe.payment_state();
        let webhook_secret = cfg.stripe.webhook_secret.clone();
        let tolerance_seconds = cfg.stripe.webhook_tolerance_seconds;
        
        tokio::spawn(async move {
            if let Err(e) = webhook_server::run_webhook_server(
                webhook_port,
                payment_state,
                webhook_secret,
                tolerance_seconds,
            ).await {
                tracing::error!("Webhook server failed: {}", e);
            }
        });
        
        tracing::info!(
            webhook_port = webhook_port,
            "Webhook HTTP server starting on port {}",
            webhook_port
        );
    } else {
        tracing::warn!("Webhook secret not configured - webhook server will not start");
    }

    // Enable gRPC reflection so tools like grpcurl can discover services and methods
    let reflection_svc = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(pb::FILE_DESCRIPTOR_SET)
        .build_v1()?; // use v1 to satisfy grpcurl reflection

    // Build server, optionally with TLS
    let mut builder = Server::builder()
        .http2_keepalive_interval(Some(cfg.keep_alive_interval))
        .http2_keepalive_timeout(Some(cfg.keep_alive_timeout))
        .max_connection_age(cfg.max_connection_age);

    if cfg.tls_enable {
        // Ensure cert files exist, generate self-signed if missing
        let cert_path = Path::new(&cfg.tls_cert_path);
        let key_path = Path::new(&cfg.tls_key_path);
        let ca_path = {
            let stem = cert_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("cert");
            let ca_file = format!("{stem}.ca.pem");
            cert_path.with_file_name(ca_file)
        };

        if !cert_path.exists() || !key_path.exists() {
            tracing::warn!(
                cert=%cert_path.display(), key=%key_path.display(),
                "TLS enabled but certificate or key not found; generating CA and server certificate"
            );
            if let Some(parent) = cert_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Some(parent) = key_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Some(parent) = ca_path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            // Generate a simple CA certificate
            let mut ca_params = rcgen::CertificateParams::default();
            ca_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "CDK Stripe Dev CA");
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
                rcgen::KeyUsagePurpose::DigitalSignature,
            ];
            let ca_cert = rcgen::Certificate::from_params(ca_params).expect("generate CA cert");

            // Generate a server certificate signed by the CA
            let mut server_params =
                rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]);
            server_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "localhost");
            server_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "127.0.0.1");
            server_params
                .extended_key_usages
                .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);

            let server_cert =
                rcgen::Certificate::from_params(server_params).expect("generate server cert");
            let server_cert_pem = server_cert
                .serialize_pem_with_signer(&ca_cert)
                .expect("serialize server cert pem");
            let server_key_pem = server_cert.serialize_private_key_pem();
            let ca_cert_pem = ca_cert.serialize_pem().expect("serialize ca pem");

            // Write files
            fs::write(&cert_path, server_cert_pem).expect("write server cert pem");
            fs::write(&key_path, server_key_pem).expect("write server key pem");
            fs::write(&ca_path, ca_cert_pem).expect("write ca cert pem");
        }

        // Load server cert + chain (append CA so clients receive the issuer)
        let mut chain_pem = fs::read(&cfg.tls_cert_path)?;
        if let Ok(ca_pem) = fs::read(&ca_path) {
            chain_pem.extend_from_slice(b"\n");
            chain_pem.extend_from_slice(&ca_pem);
        }

        let key = fs::read(&cfg.tls_key_path)?;
        let identity = Identity::from_pem(chain_pem, key);
        builder = builder.tls_config(ServerTlsConfig::new().identity(identity))?;
        tracing::info!(
            addr=%addr,
            cert=%cfg.tls_cert_path,
            key=%cfg.tls_key_path,
            ca=%ca_path.display(),
            "Starting TLS-enabled gRPC server (with CA chain)"
        );
    } else {
        tracing::info!(addr=%addr, "Starting plaintext gRPC server");
    }

    builder
        .add_service(reflection_svc)
        .add_service(
            pb::cdk_payment_processor::cdk_payment_processor_server::CdkPaymentProcessorServer::new(
                svc,
            ),
        )
        .serve(addr)
        .await?;

    Ok(())
}