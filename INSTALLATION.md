# Installation

## 1. Install build dependencies

Node.js and a JDK (21+) are assumed to already be installed. Install the
remaining tools the build scripts need:

```bash
# Rust toolchain (cargo, rustc)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# wasm-pack — builds the WASM binding
cargo install wasm-pack

# Kotlin compiler + linter — for the JVM binding (macOS / Homebrew)
brew install kotlin ktlint
```

## 2. Build

Run from the `src/` directory:

```bash
cd src

# CLI binary -> target/release/cfn-validate
cargo build --locked --release -p cfn-validate

# WASM binding (Node.js) -> bindings-wasm/dist/
./bindings-wasm/build.sh

# JVM binding (Kotlin/Java) -> bindings-jvm/generated/cloudformation-validate.jar
./bindings-jvm/build.sh
```

## 3. Download and verify release artifacts

Signed artifacts are attached to each GitHub release. A release contains the
artifacts (`cloudformation-validate`,
`cloudformation-validate.jar`) plus, for each one, a detached signature
(`<artifact>.sig`), the public key (`signing-key.pem`), and the key's SHA-256
fingerprint (`signing-key.pem.sha256`). Artifacts are signed with an AWS KMS RSA
key (`RSASSA_PKCS1_V1_5_SHA_256`).

Download the artifact you want, its `.sig`, and `signing-key.pem` from the same
release, then verify the signature:

```bash
openssl dgst -sha256 -verify signing-key.pem -signature [artifact].sig [artifact]
# openssl dgst -sha256 -verify signing-key.pem -signature cloudformation-validate.zip.sig cloudformation-validate.zip
```

A valid artifact prints `Verified OK`. Any other output means verification
failed - do not use the artifact.

Optionally, confirm the bundled key is the real signing key by matching its
fingerprint against one you trust:

```bash
openssl pkey -pubin -in signing-key.pem -outform DER | openssl dgst -sha256
cat signing-key.pem.sha256
```

The two values must match.
