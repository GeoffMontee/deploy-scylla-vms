# Coding Agent Guide

This repository is currently a planning and documentation scaffold. Follow this
guide when adding or changing implementation, infrastructure, tests, or
documentation. Do not claim that planned commands, modules, or checks exist
until they do.

## Scope and decision rules

- Read `README.md`, `PLAN.md`, `VERSION`, and `RELEASE_NOTES.md` before making a
  behavioral change.
- Keep changes within the requested scope. Do not combine feature work with
  unrelated refactoring or generated-file churn.
- Treat `PLAN.md` as design intent, not proof of implemented behavior. If
  implementation requires a different decision, explain and update the plan or
  an appropriate design record.
- Prefer small, reviewable changes with tests. Preserve user-authored content
  unless the request explicitly replaces it.
- Never commit, push, create cloud resources, or run destructive operations
  unless the user explicitly requests that action.

## Python

- Keep `deploy_scylla_vms.py` a thin CLI entry point; put reusable behavior in
  cohesive package modules.
- Use typed interfaces and validated domain models at configuration, provider,
  Terraform JSON, inventory, and operation boundaries.
- Use `pathlib`, explicit encodings, atomic writes, restrictive permissions, and
  safe path validation for application state. Reject traversal, symlink escapes,
  invalid cluster names, and ownership/permission mismatches.
- Invoke subprocesses with argument arrays and `shell=False`. Set explicit
  working directories, controlled environments, timeouts, error handling, and
  output redaction.
- Do not log or format an environment, command, model, state object, or exception
  that may include credentials without passing it through tested redaction.
- Keep provider-specific concepts behind provider adapters. OCI is initially the
  only accepted provider; do not advertise AWS/GCP support before it exists.
- Public errors and exit codes must be stable, useful, and mapped at the CLI
  boundary. Preserve causes for protected diagnostic logs.
- Maintain compatibility with the documented Python and dependency support
  matrix once one is established. Do not silently raise minimum versions.

## Configuration and secrets

- Secret values come only from environment variables. Do not add secret
  command-line flags, plaintext config keys, persistent credential files,
  checked-in credentials, generated password files, or secret defaults.
- If a downstream tool requires a credential file, create it from the
  environment as an owner-only, short-lived runtime file, redact its path where
  useful, and remove it reliably.
- Non-secret precedence must remain explicit and tested. Unless documentation is
  deliberately updated, use CLI over environment over config/default.
- Never place secrets in fixtures, snapshots, Terraform variables committed to
  Git, Ansible inventory, operation journals, plan output, logs, examples, or
  release notes.
- Use obviously fake values in tests and docs. Add a regression test whenever a
  new potentially sensitive field crosses a logging or serialization boundary.

## Infrastructure as code

- Terraform source is authoritative for managed infrastructure; do not add
  imperative OCI creation as an untracked side path.
- Format and validate Terraform changes. Pin provider constraints deliberately
  and commit `.terraform.lock.hcl`; never add it to `.gitignore`.
- Never commit `.terraform/`, state, state backups, saved plans, crash logs, or
  generated backend credentials.
- Do not treat `.gitignore` as state configuration. Its broad Terraform patterns
  are defense-in-depth; `.terraform/` is working/cache data, not the state
  directory.
- Implement exactly one state-root precedence:
  `--state-dir` > `DEPLOY_SCYLLA_VMS_STATE_DIR` >
  `platformdirs.user_state_path("deploy-scylla-vms", appauthor=False)`.
- Keep every cluster under
  `<state-dir>/clusters/<validated-cluster-name>/`. Put Terraform working data
  and local state under `<cluster-root>/terraform/`, generated inventory and SSH
  trust data under `<cluster-root>/ansible/`, and plans, locks, logs, and
  journals in their documented subdirectories. Do not introduce an alternate
  layout without an approved plan/documentation migration.
- Never write runtime state, `.terraform/`, generated inventory, plans, locks,
  or logs into the repository source tree or an implicit current working
  directory. Stage reviewed Terraform source into the cluster working
  directory, set `-chdir`, `TF_DATA_DIR`, backend state, and plan paths to
  absolute locations below the cluster root for every applicable command.
- Preserve application-level and Terraform/backend locking. Never disable
  locking to make a test or operation pass.
- Detect state or backend metadata outside the canonical path before
  initialization. Stop on conflicts; never silently create replacement state,
  migrate, import, move, or delete unexpected state.
- Consume `terraform output -json` through a versioned, strict schema. Do not
  parse human output.
- Security rules must be least-privilege. Do not expose SSH, ScyllaDB, Manager,
  or monitoring endpoints to the public internet by default.
- Infrastructure deletions, replacements, imports, state moves, and backend
  migrations require a reviewed plan, identity/drift checks, explicit operator
  intent, and appropriate recovery/backup notes.
- Unit and normal CI tests must not authenticate to OCI or modify real
  infrastructure. Live tests must be separately gated, isolated, tagged,
  budgeted, and verified for teardown.

## Ansible

- Keep inventories generated deterministically from validated Terraform JSON
  outputs. Generated inventories are runtime artifacts and must not be committed.
- Refresh and validate inventory before sensitive or destructive actions and
  whenever Terraform output changes. Stop on identity, membership, host-key, or
  topology conflicts.
- Roles and playbooks must be idempotent, support safe reruns, and use deliberate
  handlers, conditions, check-mode behavior, serial limits, and health gates.
- Pin collections and external roles. Validate ScyllaDB role behavior against
  current official docs and upstream source; GitHub wiki guidance can be stale.
- Do not disable SSH host-key checking. Do not embed private keys, Vault
  passwords, or tokens in inventory or process arguments.
- Node lifecycle and rolling maintenance must operate on stable node IDs, not
  changing list positions or IP addresses.

## Safety and operations

- Classify every operation as read-only, mutating, sensitive, or destructive.
  New operations must use the common registry, lock, reconciliation, planning,
  confirmation, journaling, and verification interfaces.
- Dry-run and plan output must clearly distinguish validated facts, intended
  changes, unknown values, and checks that were not performed.
- `--yes` or automation mode must not bypass cluster identity, drift,
  concurrency, health, or destructive-scope checks.
- Destructive workflows must show exact cluster/node stable IDs, reconcile
  Terraform/inventory/live state, verify backup policy where applicable, and
  require explicit confirmation.
- Stateful ScyllaDB nodes must be decommissioned/replaced using
  version-appropriate official procedures before infrastructure removal.
- Rolling operations default to one eligible node at a time and stop on failed
  health gates. Do not combine unrelated upgrade classes.
- Make interrupted steps resumable only after revalidation; never infer success
  solely from an old journal entry.

## Test expectations

Add or update tests at the layer where behavior is owned:

- **Unit:** parsing, precedence, validation, canonical path/traversal checks,
  stable identity, redaction, fully anchored Terraform command construction,
  unexpected-state detection, state locks, drift classification, operation
  phase decisions, and exit-code mapping. Use fakes; no network or real
  infrastructure.
- **Contract:** Terraform JSON schemas, generated inventory, provider adapter
  request/response fixtures, and external tool version/error behavior.
- **Integration:** disposable local Terraform/Ansible fixtures, syntax checks,
  check mode, inventory validation, idempotence, failure injection, and resume.
- **Live/end-to-end:** opt-in only in an approved isolated OCI environment; test
  deploy, no-op convergence, lifecycle changes, conflict refusal, recovery, and
  destroy with cleanup verification.

For a code change, run the narrow relevant tests and the broadest available
format, lint, type-check, and test suite proportionate to risk. If tools or
commands have not yet been established, do not invent successful results:
document what was manually validated and what remains. Tests must cover failure
and refusal paths, not only success.

## Formatting and quality

- Adopt and document one formatter, linter, and static type checker when Python
  scaffolding is introduced; configure them in project metadata and run them in
  CI. Until then, follow standard Python style and keep Markdown readable.
- Terraform must pass its formatter and validation; Ansible YAML should pass the
  selected YAML/Ansible lint rules once configured.
- Avoid broad exception catches, mutable global state, implicit subprocess
  environments, time-dependent tests, and order-dependent host collections.
- Comment the reason for safety constraints and non-obvious operational rules,
  not obvious syntax.

## Documentation, releases, and compatibility

- Update user documentation whenever CLI arguments, environment variables,
  safety behavior, state layout, supported versions, or operational workflows
  change.
- A Markdown document that already contains a table of contents must update it
  in the same change whenever included headings are added, renamed, removed, or
  reordered. A heading edit is incomplete while its TOC is stale.
- Use GitHub-compatible generated anchor fragments and verify every TOC target
  against the document's actual headings. Account for punctuation, inline code,
  numeric/version prefixes, Unicode punctuation, and GitHub's duplicate-heading
  suffixes; prefer a small unique-heading rename over fragile duplicate links
  when that improves durability.
- Keep TOC depth consistent and useful: include the document's main sections and
  only the subsections needed for navigation. Do not include the
  `Table of contents` heading itself, link multiple entries to the wrong
  duplicate anchor, or leave stale entries after reordering.
- Maintain TOCs manually unless and until this repository adds and approves a
  generator/check command. Do not invent such tooling or claim that a TOC check
  currently exists.
- Add a TOC to a new Markdown document when it is substantial enough to benefit
  from navigation: normally six or more meaningful H2/H3 sections, roughly 200
  or more lines, or a shorter document whose nested structure or repeated
  reference use makes navigation difficult. Small linear documents do not need
  one.
- Keep examples clearly marked planned until runnable, and test runnable examples
  once implementation exists.
- Update `RELEASE_NOTES.md` for user-visible changes. Update `VERSION` only when
  the requested release/versioning decision requires it; keep it a single
  newline-terminated version string.
- Follow the established versioning policy once documented. Call out breaking
  changes to CLI, config, state, output/inventory schemas, and exit codes, and
  provide migration guidance.
- Keep authoritative resource links current. Prefer official ScyllaDB, OCI,
  Terraform, Ansible, Python, PyPA, OWASP, and NIST sources over third-party
  tutorials.

## Before handing off

- Review the complete diff and repository status.
- Verify no secrets, local state, generated inventory, plans, caches, or
  credentials were added.
- Report files changed, tests/checks actually run, safety or compatibility
  implications, and any blockers. Do not claim unrun validation.
