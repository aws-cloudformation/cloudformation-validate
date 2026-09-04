# Installation

`cloudformation-validate` is distributed as a prebuilt command-line tool and as packages for Rust, Node.js, Python,
Go, and the JVM. All distributions contain the validation rules and CloudFormation resource schemas they need, so
validation runs offline after installation without AWS credentials or runtime downloads.

## Command-line interface

Prebuilt `cfn-validate` binaries are attached to every release on the
[GitHub Releases page](https://github.com/aws-cloudformation/cloudformation-validate/releases), with the newest release
shown first. Open that release and download the asset for your platform:

| Platform | Release asset |
|----------|---------------|
| Linux x86-64 | `cfn-validate-<version>-linux-x64` |
| Linux ARM64 | `cfn-validate-<version>-linux-aarch64` |
| macOS Apple silicon | `cfn-validate-<version>-darwin-aarch64` |
| macOS Intel | `cfn-validate-<version>-darwin-x64` |
| Windows x86-64 | `cfn-validate-<version>-win32-x64.exe` |
| Windows ARM64 | `cfn-validate-<version>-win32-aarch64.exe` |

On Linux or macOS, make the downloaded file executable, rename it to `cfn-validate`, and move it to a directory on
`PATH`. On Windows, rename it to `cfn-validate.exe` and move it to a directory on `PATH`.

After installation, validate a template or a directory of templates:

```bash
cfn-validate template.yaml
cfn-validate ./templates/
```

See the [CLI reference](src/cfn-validate/README.md) for all engines, filters, output formats, custom rules, and exit
codes.

## Language bindings

Package-manager installation is recommended: it selects the compatible native artifact and resolves any runtime
dependencies. Use an explicit version in applications that require reproducible builds.

### Rust

The Rust library is published to [crates.io as `cloudformation-validate`](https://crates.io/crates/cloudformation-validate)
and requires Rust 1.96 or later.

```bash
# Latest release
cargo add cloudformation-validate

# Specific release (replace <version>)
cargo add 'cloudformation-validate@=<version>'
```

See the [Rust API and examples](src/bindings-rust/README.md).

### Node.js

The Node.js/WASM package is published to
[npm as `@aws/cloudformation-validate`](https://www.npmjs.com/package/@aws/cloudformation-validate) and requires
Node.js 20 or later.

```bash
# Latest release
npm install @aws/cloudformation-validate

# Specific release (replace <version>)
npm install '@aws/cloudformation-validate@<version>'
```

See the [Node.js API and examples](src/bindings-wasm/README.md).

### Python

Production versions are published to [PyPI](https://pypi.org/project/cloudformation-validate/); prereleases are
published to [TestPyPI](https://test.pypi.org/project/cloudformation-validate/). The package requires Python 3.10 or
later, and its platform-specific wheels have no runtime package dependencies.

```bash
# Latest production release from PyPI
python3 -m pip install cloudformation-validate

# Latest prerelease from TestPyPI
python3 -m pip install \
  --index-url https://test.pypi.org/simple/ \
  --pre cloudformation-validate

# Specific production release (replace <version>)
python3 -m pip install 'cloudformation-validate==<version>'
```

See the [Python API and examples](src/bindings-python/README.md).

### Go

The published [Go module](https://pkg.go.dev/github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go)
requires Go 1.26 or later, cgo, and a C linker. It currently contains native libraries for Linux x86-64, macOS Apple
silicon, and Windows x86-64; Windows uses the MinGW-w64 GNU ABI.

```bash
# Latest release
go get github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go@latest

# Specific release (replace <version>)
go get 'github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go@v<version>'
```

```go
import cfnvalidate "github.com/aws-cloudformation/cloudformation-validate/src/bindings-go/go"
```

See the [Go API and examples](src/bindings-go/README.md).

### JVM (Kotlin/Java)

The JVM library is published to
[Maven Central as `software.amazon.cloudformation:cloudformation-validate`](https://central.sonatype.com/artifact/software.amazon.cloudformation/cloudformation-validate)
and requires JDK 21 or later. The jar includes native libraries for all supported platforms; Maven or Gradle resolves
JNA, Gson, and the Kotlin standard library.

Gradle (Kotlin DSL):

```kotlin
dependencies {
    implementation("software.amazon.cloudformation:cloudformation-validate:latest.release")
}
```

Gradle (Groovy DSL):

```groovy
dependencies {
    implementation 'software.amazon.cloudformation:cloudformation-validate:latest.release'
}
```

Maven:

```xml
<dependency>
    <groupId>software.amazon.cloudformation</groupId>
    <artifactId>cloudformation-validate</artifactId>
    <version>[0,)</version>
</dependency>
```

`latest.release` and `[0,)` select the newest published version. Replace them with a version shown on Maven Central to
pin the dependency. See the [JVM API and examples](src/bindings-jvm/README.md).

## Versioned GitHub release assets

The [GitHub Releases page](https://github.com/aws-cloudformation/cloudformation-validate/releases) also publishes raw,
versioned artifacts. Package-manager installation is usually easier, but these assets support vendoring and offline
installation (`<version>` is the release tag):

* `cloudformation-validate-<version>.jar` - JVM binding
* `cloudformation-validate-wasm-<version>.zip` - Node.js/WASM package
* `cloudformation_validate-<version>-py3-none-<platform>.whl` - Python wheel for one native target; beta release tags
  use Python's `<version>b0` form
* `cloudformation-validate-go-<version>.zip` - Go module with the supported native libraries
* `cfn-validate-<version>-<os>-<arch>` - CLI binary (with `.exe` on Windows)

### Verify a downloaded release asset

Each raw artifact has a detached `<artifact>.sig` signature. The same release includes `signing-key.pem` and its
`signing-key.pem.sha256` fingerprint. Download all three files from that release and verify with OpenSSL:

```bash
openssl dgst -sha256 \
  -verify signing-key.pem \
  -signature '<artifact>.sig' \
  '<artifact>'
```

A valid artifact prints `Verified OK`. Do not use an artifact if verification fails.

To compare the bundled public key with a fingerprint obtained from a trusted source:

```bash
openssl pkey -pubin -in signing-key.pem -outform DER | openssl dgst -sha256
cat signing-key.pem.sha256
```

The SHA-256 values must match.

## Developer setup

The installation methods above do not require a source checkout or development toolchain. Contributors building or
testing the project from source need the tools below. Pinned versions live in
[`.github/workflows/configs.yml`](.github/workflows/configs.yml) and
[`src/rust-toolchain.toml`](src/rust-toolchain.toml); matching them avoids environment drift.

### Required tools

| Tool                            | Version | Required for                                              | Notes                                                                                                           |
|---------------------------------|---------|-----------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| Rust (`cargo`, `rustc`)         | 1.96.0  | everything                                                | Pinned by `src/rust-toolchain.toml`; rustup installs it for you                                                 |
| `rustfmt`                       | bundled | `cargo fmt` lint                                          | Declared as a component in the toolchain file                                                                   |
| `wasm32-unknown-unknown` target | bundled | WASM binding                                              | Added automatically by the toolchain file                                                                       |
| `wasm-pack`                     | 0.15.0  | WASM binding build/test                                   | `cargo install`                                                                                                 |
| `cargo-about`                   | 0.9.1   | third-party license generation (Build Artifacts workflow) | `cargo install`                                                                                                 |
| `cargo-audit`                   | 0.22.2  | dependency vulnerability audit                            | `cargo install`                                                                                                 |
| Node.js + npm                   | 22.x    | WASM binding build/test                                   | `npm` ships with Node                                                                                           |
| JDK                             | 21+     | JVM binding build/test                                    | Corretto in CI; provides `java` and `jar`                                                                       |
| Kotlin (`kotlinc`)              | 2.4.0   | JVM binding build                                         |                                                                                                                 |
| `ktlint`                        | 1.8.0   | JVM binding formatting                                    |                                                                                                                 |
| Gradle                          | 9.6.1   | JVM binding build/test                                    | Must be on `PATH` - `bindings-jvm/build.sh` and the JVM test runner invoke `gradle`                             |
| Python                          | 3.10+   | Python binding build/test, license generation, `scripts/` | `setuptools` for the wheel build; no other packages required                                                    |
| Go                              | 1.26+   | Go binding build/test                                     | cgo must be enabled (default); Windows also needs `rustup target add x86_64-pc-windows-gnu` and MinGW-w64 `gcc` |
| `uniffi-bindgen-go`             | 0.7.1   | Go binding generation                                     | `cargo install --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.7.1+v0.31.0`                    |
| `git`, `curl`, `openssl`        | -       | source control, fetching JVM deps, verifying releases     | Usually preinstalled                                                                                            |
