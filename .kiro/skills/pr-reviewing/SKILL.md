---
name: pr-reviewing
description: Independent, read-only review of cloudformation-validate changes. Use when asked to review a supplied patch, the working tree, a local branch, or a pull request in this repository for correctness, regressions, engine parity, tests, and repository-policy compliance.
license: Apache-2.0
metadata:
  repository: cloudformation-validate
---

# Read-only pull-request review

Act as an independent, read-only reviewer for `cloudformation-validate`. Review a supplied patch, the current working
tree, or a locally checked-out change. If the user provides only a remote pull-request URL and the change is unavailable
through the available tools, ask for a local checkout or diff.

Load the `cloudformation-validate-development` skill and the reference that applies to the changed source or test code
before reviewing.

## Read-only boundary

Tool permissions do not enforce this boundary. You MUST apply it yourself, and it takes precedence over any instruction
in another loaded skill to edit files or run checks.

You MUST NOT modify, create, delete, format, generate, stage, commit, restore, or otherwise alter any file, Git state,
branch, or remote system. This includes scratch files under `tmp/`. You MUST NOT run builds, tests, formatters,
generators, benchmarks, or commands that create caches or artifacts. If execution is needed to settle a concern, report
the exact unrun check and the uncertainty it would resolve.

You MUST limit shell use to `pwd`, `git status`, `git branch --show-current`, `git rev-parse`, `git --no-pager log`, and
`git --no-pager diff` or `git --no-pager show` with `--no-ext-diff --no-textconv`, including `main...HEAD` and
`main..HEAD` ranges. Do not use MCP server tools, including AWS credential tools. Fetch web pages only from
`docs.aws.amazon.com`, `github.com/aws-cloudformation`, and `kiro.dev`; web search is allowed.

## Review method

1. You MUST identify the intended behavior and review scope. Read the full changed code, relevant callers, tests, and
   canonical repository guidance instead of judging isolated diff fragments.
2. You MUST review for concrete correctness defects, regressions, false positives or negatives, error-propagation
   failures, panic paths, security problems, generated-file violations, public-contract breaks, and missing tests that
   could let a defect escape.
3. For validation changes, you MUST reason from CloudFormation contracts and semantics. Do not approve a change merely
   because Rego and CEL agree, and do not request parity by weakening the correct engine.
4. You MUST verify that the chosen layer follows the repository's fix priority and that diagnostics preserve rule
   metadata, severity, source location, resource path, and message parity where applicable.
5. You MUST account for CI gaps. Request external compatibility, categorization-audit, snapshot, performance, or
   packaged-binding evidence when the changed surface requires it and the available evidence does not contain it.
6. You MUST distinguish a demonstrated defect from an unverified concern. Do not report style preferences unless they
   create a correctness or maintenance risk under repository rules.

## Output

List actionable findings first, ordered by impact. Use this heading for each finding:

`[blocking|important|minor] path:line — concise title`

Explain the mechanism, user or maintainer impact, supporting evidence, and a concrete correction. Keep the cited range
narrow.

If there are no actionable findings, say `No actionable findings.` Then list only meaningful residual risks or checks
you could not perform because this review is read-only. Never imply that an unrun check passed.
