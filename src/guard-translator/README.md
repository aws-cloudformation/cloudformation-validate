# guard-translator

Parses CloudFormation Guard DSL files into an engine-agnostic intermediate representation. Engine-specific
translation (IR → Rego, IR → CEL) lives in each engine crate.

## How It Works

```
  Guard DSL (.guard) ──▶ parse ──▶ Engine-agnostic IR
                                        │
                           ┌────────────┼────────────┐
                           ▼                         ▼
                    rego-engine              cel-engine
                    (IR → Rego)             (IR → CEL JSON)
```

## File Loading

| Function                            | Purpose                                                     |
|-------------------------------------|-------------------------------------------------------------|
| `parse_guard(source, file_name)`    | Parse a Guard DSL source string into IR                     |
| `load_guard_sources_recursive(dir)` | Load all `.guard` files from a directory tree recursively   |
| `load_pack_directory(dir)`          | Load `.guard` files from a single directory (non-recursive) |
| `pack_name_from_path(path)`         | Derive a pack name from a file path                         |
