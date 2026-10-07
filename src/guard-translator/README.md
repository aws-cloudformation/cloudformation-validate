# guard-translator

Evaluates CloudFormation Guard DSL files with the Guard evaluator itself and turns its report into engine-agnostic
findings. Every rule engine calls this one code path, so a Guard rule produces the same findings whichever engine runs
it, and those findings are the ones `cfn-guard validate` reports.

## How It Works

```
  Guard DSL (.guard) ──▶ GuardRuleFile::parse ──▶ parsed once, syntax errors reported at load time
                                                        │
  SemanticModel::authored_template_json() ──▶ GuardRuleFile::evaluate ──▶ Vec<GuardFinding>
                                                        │
                                   validation-engine GuardRuleSet ──▶ Vec<Diagnostic>
```

- Parsing and evaluation are done by [`cloudformation-guard-lang`](https://crates.io/crates/cloudformation-guard-lang),
  the crate `cfn-guard` is built on, so the whole Guard language is supported and no Guard semantics are
  re-implemented here.
- Rules are evaluated against the template as the author wrote it, with intrinsic functions in long form - the same
  view `cfn-guard` evaluates, rendered by `template-model`.
- Each failed check becomes a `GuardFinding` carrying the rule name, the slash-separated template path the check was
  evaluated at (`Resources/Bucket/Properties/BucketName`), the unresolved query remainder when a property is missing,
  the author's `<<message>>`, and the check text. `validation-engine` maps findings onto diagnostics (entity, property
  path, source span, `guard:<pack>` category).

## API

| Item                                | Purpose                                                              |
|-------------------------------------|----------------------------------------------------------------------|
| `GuardRuleFile::parse(name, source)` | Parse a rule file; records each rule's name and first custom message |
| `GuardRuleFile::evaluate(template)`  | Evaluate the file against authored template JSON                     |
| `GuardRuleFile::rules()`             | The declared rules, for rule listings                                |
| `GuardRuleFile::pack()`              | The pack name derived from the file name                             |
| `load_guard_sources_recursive(dir)`  | Load all `.guard` files from a directory tree recursively            |
| `pack_name_from_path(path)`          | Derive a pack name from a file path                                  |
