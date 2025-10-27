# CDK Stripe Payment Processor

A standalone gRPC service that implements the CDK payment processor protocol for Stripe payment processing. This service bridges the CDK payment processor interface to Stripe's REST API for traditional payment processing.

**Extracted from:** [cdk-blink-payment-processor](https://github.com/asmogo/cdk-blink-payment-processor)

## Features

- **Stripe Payment Intent Creation**: Create payment intents for incoming payments
- **Payment Status Checking**: Query payment intent status
- **gRPC Interface**: Implements the standard CDK payment processor protocol
- **TLS Support**: Optional TLS encryption for gRPC connections
- **Automatic Retry Logic**: Built-in retry mechanism with exponential backoff for transient errors
- **Idempotency Support**: Safe retries using Stripe idempotency keys

## Requirements

- Rust (stable toolchain) and Cargo
- protoc (Protocol Buffers compiler) available on PATH
  - macOS: `brew install protobuf`
  - Linux: install distro package (e.g., `apt-get install -y protobuf-compiler`)
- Stripe API account and secret key
- Network access to Stripe API (https://api.stripe.com)

## Setup and Configuration

Configuration can be provided via a config file at the repository root or environment variables. Default values are in [`src/settings.rs`](src/settings.rs).

### Configuration File

Create a [`config.toml`](config.toml) file:

```toml
# Stripe configuration
[stripe]
api_key = "sk_test_..."           # Stripe secret key (required)
account_id = ""                   # Optional: Stripe Connect account ID
stripe_version = ""               # Optional: API version override (e.g., "2023-10-16")
timeout_ms = 15000                # Request timeout in milliseconds
webhook_secret = "whsec_..."      # Stripe webhook signing secret

# gRPC server configuration
server_port = 50051
keep_alive_interval = "30s"
keep_alive_timeout = "10s"
max_connection_age = "30m"

# TLS configuration
tls_enable = false
tls_cert_path = "certs/server.crt"
tls_key_path = "certs/server.key"
```

### Environment Variables

Environment variables override file values:

- `STRIPE_API_KEY` - Stripe secret key (required)
- `STRIPE_ACCOUNT_ID` - Stripe Connect account ID (optional)
- `STRIPE_VERSION` - API version override (optional)
- `STRIPE_TIMEOUT_MS` - Request timeout in milliseconds
- `STRIPE_WEBHOOK_SECRET` - Webhook signing secret
- `SERVER_PORT` - gRPC server port
- `TLS_ENABLE` - Enable TLS: "true" or "false"
- `TLS_CERT_PATH` - Path to TLS certificate
- `TLS_KEY_PATH` - Path to TLS private key
- `KEEP_ALIVE_INTERVAL` - e.g. "45s"
- `KEEP_ALIVE_TIMEOUT` - e.g. "15s"
- `MAX_CONNECTION_AGE` - e.g. "1h"

### Example Run

```bash
STRIPE_API_KEY=sk_test_your_key \
SERVER_PORT=50051 \
RUST_LOG=info \
cargo run --release
```

## Build

The build script compiles the proto during build using tonic-build (prost).

- Proto: [`src/payment_processor.proto`](src/payment_processor.proto)
- Build script: [`build.rs`](build.rs)

Build release:
```bash
cargo build --release
```

## Run

By default the server listens on 0.0.0.0:50051.

```bash
RUST_LOG=info cargo run --release
```

## gRPC API

### Service: cdk_payment_processor.CdkPaymentProcessor

Generated from [`src/payment_processor.proto`](src/payment_processor.proto)

**Implemented RPCs:**
- `GetSettings(EmptyRequest) -> SettingsResponse` - Returns Stripe provider settings
- `CreatePayment(CreatePaymentRequest) -> CreatePaymentResponse` - Creates a Stripe payment intent
- `CheckIncomingPayment(CheckIncomingPaymentRequest) -> CheckIncomingPaymentResponse` - Checks payment intent status

**Unimplemented RPCs** (Stripe is for incoming payments only):
- `GetPaymentQuote` - Not applicable
- `MakePayment` - Not applicable
- `CheckOutgoingPayment` - Not applicable
- `WaitIncomingPayment` - Requires webhook setup (not implemented)

**Notes:**
- Currency unit is "usd" (USD cents)
- PaymentIdentifier uses type `CUSTOM_ID` with payment intent IDs
- Amount conversion: 1 sat = 1 cent (adjust as needed for production)

## Usage Examples (grpcurl)

All examples assume a local server on 127.0.0.1:50051 with plaintext gRPC.

**GetSettings:**
```bash
grpcurl -plaintext -d '{}' 127.0.0.1:50051 cdk_payment_processor.CdkPaymentProcessor/GetSettings
```

**CreatePayment (1000 cent/$10 payment intent):**
```bash
grpcurl -plaintext -d '{
  "unit": "usd",
  "options": { 
    "bolt11": { 
      "description": "test payment", 
      "amount": 1000
    } 
  }
}' 127.0.0.1:50051 cdk_payment_processor.CdkPaymentProcessor/CreatePayment
```

**CheckIncomingPayment (by payment intent ID):**
```bash
grpcurl -plaintext -d '{
  "request_identifier": { 
    "type": "CUSTOM_ID", 
    "id": "pi_..." 
  }
}' 127.0.0.1:50051 cdk_payment_processor.CdkPaymentProcessor/CheckIncomingPayment
```

## Project Structure

```
cdk-stripe-payment-processor/
├── src/
│   ├── main.rs              # Entry point and server setup
│   ├── pb.rs                # Protobuf generated code inclusion
│   ├── settings.rs          # Configuration management
│   ├── payment_processor.proto  # gRPC service definition
│   ├── server/
│   │   └── mod.rs           # gRPC service implementation
│   └── stripe/
│       ├── mod.rs           # Stripe provider module
│       ├── rest.rs          # Stripe REST API client
│       ├── types.rs         # Stripe data types
│       ├── errors.rs        # Stripe error handling
│       ├── webhook.rs       # Webhook handling (stub)
│       └── metrics.rs       # Metrics placeholders
├── build.rs                 # Protobuf build script
├── Cargo.toml              # Dependencies
├── config.toml             # Configuration file
└── README.md               # This file
```

## Stripe Integration Details

### REST API Operations

- `create_payment_intent` - Create a PaymentIntent for incoming payments
- `confirm_payment_intent` - Confirm a PaymentIntent
- `create_refund` - Create a refund (infrastructure in place)
- `retrieve_intent` - Retrieve a PaymentIntent by ID

## License

MIT

## Authors

- asmo <asmogo@protonmail.com>