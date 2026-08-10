# Benchmark Comparison

Generated: 2026-04-23T00:09:14Z

## Host

- **os**: Darwin 25.4.0
- **arch**: arm64
- **python**: 3.12.10
- **rustc**: rustc 1.93.1 (01f6ddf75 2026-02-11) (Homebrew)
- **node**: v22.22.2
- **java**: openjdk version "21.0.2" 2024-01-16
- **iterations/template**: 50
- **corpus fingerprint**: `1a83e4bfadd4724ac9af8e3fa41776dddda9ccb3df3a5a4f8eb7d5d14048859e` (343 files)

Three phases are measured with the host language's own clock so numbers are directly comparable across native / wasm / jvm:
1. **Init** - construct `SchemaValidator + engine` (one-time setup).
2. **Template Modeling** - `SemanticModel::parse(bytes)` (standalone parse of one template).
3. **Validate** - full `validate(bytes)` call (everything - re-parses + schema + rules + finalize).

Each phase reports cold (first iteration per template) and warm (subsequent iterations). The Rust-internal sub-phase breakdown inside validate (model_build / schema_validate / rule_evaluation / diagnostic_finalize) is surfaced under Per-Engine Detail. `engine_internal` is the Rust-internal total (identical across bindings); `wall_clock` is the host-timed validate total; `binding_overhead = wall_clock − engine_internal`.

## Table of Contents

- [Executive Summary](#executive-summary--p99-per-phase-ms)
- [REGO Engine](#rego-engine)
- [CEL Engine](#cel-engine)
- [Data Sources](#data-sources)

## Executive Summary - p99 per phase (ms)

One-glance view. **Init** shows the cold (first) construction cost - paid once per process. **Model** and **Validate** show warm p99 - the steady-state consumer-visible latency (warm == cold when iterations=50). Detailed breakdowns are in the per-engine sections below.

### REGO

| Binding | Init cold (ms) | Model warm p99 (ms) | Validate warm p99 (ms) | Throughput |
|---|---|---|---|---|
| Native Rust | 98.7990 | 1.4170 | 26.7810 | 89.22 |
| WASM (Node.js) | 245.5249 | 1.6749 | 30.9828 | 78.41 |
| JVM (JNI) | 652.8883 | 1.6132 | 28.8626 | 93.91 |

### CEL

| Binding | Init cold (ms) | Model warm p99 (ms) | Validate warm p99 (ms) | Throughput |
|---|---|---|---|---|
| Native Rust | 80.3232 | 1.3893 | 15.9470 | 101.06 |
| WASM (Node.js) | 200.4493 | 1.6915 | 18.6302 | 84.64 |
| JVM (JNI) | 386.1712 | 1.6436 | 16.2913 | 90.89 |

## REGO Engine

### Initialization - schema + engine construction (ms)

Cold pays V8 WASM codegen / JVM class-loading the first time; warm is subsequent constructions in the same process.

**Cold** - first construction (ms)

| Binding | Cold (ms) |
|---|---|
| Native Rust | 98.7990 |
| WASM (Node.js) | 245.5249 |
| JVM (JNI) | 652.8883 |

**Warm** - subsequent constructions (ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 72.2984 | 92.6740 | 101.0990 |
| WASM (Node.js) | 81.6934 | 88.0486 | 89.3776 |
| JVM (JNI) | 77.0370 | 85.2876 | 85.4838 |

**Breakdown** - schema init vs engine init (ms)

| Binding | Schema median | Schema p99 | Engine median | Engine p99 |
|---|---|---|---|---|
| Native Rust | 37.8406 | 60.0234 | 34.3924 | 40.9595 |
| WASM (Node.js) | 39.4455 | 80.7605 | 42.2046 | 88.5216 |
| JVM (JNI) | 40.2307 | 326.4579 | 36.8695 | 48.6414 |

### Template Modeling - host-timed `SemanticModel::parse` (ms)

Host timer around `SemanticModel::parse` (bytes → resolved model). Standalone measurement; does not include the re-parse inside `validate()`.

**Cold** - first iteration per template (ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 0.0594 | 1.6528 | 2.1252 |
| WASM (Node.js) | 0.0675 | 1.9258 | 2.5231 |
| JVM (JNI) | 0.0746 | 1.7334 | 2.5380 |

**Warm** - subsequent iterations per template (ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 0.0310 | 1.4170 | 2.0136 |
| WASM (Node.js) | 0.0416 | 1.6749 | 2.4030 |
| JVM (JNI) | 0.0443 | 1.6132 | 2.3158 |

### Validation - full `validate()` call (wall_clock per template, ms)

Host-timer around the full `validate()` call - the latency a consumer sees.

**Cold** - first iteration per template (ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 2.1650 | 28.3828 | 2891.4156 |
| WASM (Node.js) | 2.3051 | 31.6824 | 2345.0003 |
| JVM (JNI) | 2.1755 | 28.6712 | 1107.9574 |

**Warm** - subsequent iterations per template (ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 1.8219 | 26.7810 | 2449.7611 |
| WASM (Node.js) | 2.1930 | 30.9828 | 2673.8943 |
| JVM (JNI) | 1.9799 | 28.8626 | 2202.6841 |

**Throughput** (recomputed = ok × iterations / wall_time)

| Binding | Throughput (val/sec) |
|---|---|
| Native Rust | 89.22 |
| WASM (Node.js) | 78.41 |
| JVM (JNI) | 93.91 |

### Sub-phases (per-template medians across iterations, ms)

| Phase | Native Rust median | Native Rust p99 | Native Rust max | WASM (Node.js) median | WASM (Node.js) p99 | WASM (Node.js) max | JVM (JNI) median | JVM (JNI) p99 | JVM (JNI) max |
|---|---|---|---|---|---|---|---|---|---|
| engine_internal (total) | 1.8223 | 26.8219 | 2490.5580 | 2.1591 | 30.7142 | 2665.6099 | 1.9224 | 28.6220 | 2141.2624 |
| wall_clock (total) | 1.8225 | 26.8223 | 2490.5586 | 2.1969 | 31.0262 | 2665.7471 | 1.9810 | 28.8627 | 2141.5580 |
| model build | 0.0266 | 1.3604 | 1.9715 | 0.0331 | 1.6068 | 2.3244 | 0.0288 | 1.3993 | 1.9970 |
| schema validate | 0.1738 | 8.0342 | 2128.9965 | 0.2189 | 9.2618 | 2455.0399 | 0.1860 | 8.3683 | 1840.0528 |
| rule evaluation | 1.4061 | 18.7475 | 169.1265 | 1.6329 | 20.9269 | 218.0507 | 1.4863 | 20.1082 | 132.5749 |
| diagnostic finalize | 0.0028 | 0.2976 | 0.6264 | 0.0055 | 0.3407 | 0.7957 | 0.0031 | 0.3195 | 0.7038 |

### Binding overhead (wall_clock − engine_internal, ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 0.0001 | 0.0006 | 0.0026 |
| WASM (Node.js) | 0.0215 | 0.4126 | 0.9462 |
| JVM (JNI) | 0.0396 | 0.2969 | 0.4934 |

**REGO diagnostic parity:** ✅ identical across all 3 bindings (aggregate fatal=357 / errors=248 / warnings=1094 / informational=2896; 328 templates compared field-by-field across 3 binding pair(s))

## CEL Engine

### Initialization - schema + engine construction (ms)

Cold pays V8 WASM codegen / JVM class-loading the first time; warm is subsequent constructions in the same process.

**Cold** - first construction (ms)

| Binding | Cold (ms) |
|---|---|
| Native Rust | 80.3232 |
| WASM (Node.js) | 200.4493 |
| JVM (JNI) | 386.1712 |

**Warm** - subsequent constructions (ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 53.6146 | 64.4476 | 65.2476 |
| WASM (Node.js) | 56.5523 | 59.4895 | 59.6776 |
| JVM (JNI) | 56.9715 | 77.2326 | 86.3805 |

**Breakdown** - schema init vs engine init (ms)

| Binding | Schema median | Schema p99 | Engine median | Engine p99 |
|---|---|---|---|---|
| Native Rust | 36.7594 | 51.3839 | 16.8773 | 21.5523 |
| WASM (Node.js) | 37.9540 | 86.0409 | 18.6720 | 45.7338 |
| JVM (JNI) | 39.1779 | 204.2622 | 17.6821 | 35.0116 |

### Template Modeling - host-timed `SemanticModel::parse` (ms)

Host timer around `SemanticModel::parse` (bytes → resolved model). Standalone measurement; does not include the re-parse inside `validate()`.

**Cold** - first iteration per template (ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 0.0543 | 1.4403 | 2.1337 |
| WASM (Node.js) | 0.0779 | 1.7641 | 2.5607 |
| JVM (JNI) | 0.0790 | 1.6626 | 2.5059 |

**Warm** - subsequent iterations per template (ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 0.0338 | 1.3893 | 1.9569 |
| WASM (Node.js) | 0.0387 | 1.6915 | 2.4181 |
| JVM (JNI) | 0.0478 | 1.6436 | 2.3012 |

### Validation - full `validate()` call (wall_clock per template, ms)

Host-timer around the full `validate()` call - the latency a consumer sees.

**Cold** - first iteration per template (ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 2.3502 | 16.2041 | 1930.3161 |
| WASM (Node.js) | 2.7204 | 19.6045 | 3335.1073 |
| JVM (JNI) | 2.5205 | 17.5817 | 2507.8577 |

**Warm** - subsequent iterations per template (ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 2.1309 | 15.9470 | 2140.9010 |
| WASM (Node.js) | 2.5060 | 18.6302 | 2588.6355 |
| JVM (JNI) | 2.2617 | 16.2913 | 2515.7786 |

**Throughput** (recomputed = ok × iterations / wall_time)

| Binding | Throughput (val/sec) |
|---|---|
| Native Rust | 101.06 |
| WASM (Node.js) | 84.64 |
| JVM (JNI) | 90.89 |

### Sub-phases (per-template medians across iterations, ms)

| Phase | Native Rust median | Native Rust p99 | Native Rust max | WASM (Node.js) median | WASM (Node.js) p99 | WASM (Node.js) max | JVM (JNI) median | JVM (JNI) p99 | JVM (JNI) max |
|---|---|---|---|---|---|---|---|---|---|
| engine_internal (total) | 2.1324 | 15.9131 | 2109.7519 | 2.4798 | 18.4007 | 2674.5683 | 2.2159 | 16.1871 | 2511.5160 |
| wall_clock (total) | 2.1325 | 15.9134 | 2109.7521 | 2.5068 | 18.6414 | 2674.7113 | 2.2618 | 16.3184 | 2511.8181 |
| model build | 0.0271 | 1.3483 | 1.9159 | 0.0329 | 1.6354 | 2.3539 | 0.0291 | 1.4144 | 1.9674 |
| schema validate | 0.1778 | 7.9457 | 1937.4350 | 0.2173 | 9.3045 | 2352.5496 | 0.1838 | 8.3254 | 2405.1774 |
| rule evaluation | 1.8661 | 2.8978 | 85.1970 | 2.1428 | 3.2292 | 288.2850 | 1.9366 | 2.9701 | 85.9324 |
| diagnostic finalize | 0.0030 | 0.3295 | 0.6600 | 0.0054 | 0.3794 | 0.6659 | 0.0032 | 0.3203 | 0.6626 |

### Binding overhead (wall_clock − engine_internal, ms)

| Binding | median | p99 | max |
|---|---|---|---|
| Native Rust | 0.0001 | 0.0005 | 0.0010 |
| WASM (Node.js) | 0.0198 | 0.3402 | 0.8025 |
| JVM (JNI) | 0.0430 | 0.2526 | 0.4995 |

**CEL diagnostic parity:** ✅ identical across all 3 bindings (aggregate fatal=357 / errors=248 / warnings=1132 / informational=2896; 328 templates compared field-by-field across 3 binding pair(s))

## Data Sources

- rego/Native Rust: `src/cfn-validate/reports/rego/aggregate_detailed.json`
- rego/WASM (Node.js): `src/bindings-wasm/reports/rego/aggregate_detailed.json`
- rego/JVM (JNI): `src/bindings-jvm/reports/rego/aggregate_detailed.json`
- cel/Native Rust: `src/cfn-validate/reports/cel/aggregate_detailed.json`
- cel/WASM (Node.js): `src/bindings-wasm/reports/cel/aggregate_detailed.json`
- cel/JVM (JNI): `src/bindings-jvm/reports/cel/aggregate_detailed.json`

