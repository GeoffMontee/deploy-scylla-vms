# Coding Agent Guide

This repository contains an initial non-mutating Python CLI/configuration/state-
path foundation plus a broader implementation plan. Follow this guide when
adding or changing implementation, infrastructure, tests, or documentation. Do
not claim that planned operations, modules, or checks exist until they do.

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

- The supported foundation runtime is Python 3.11 or newer. Do not raise that
  minimum without a documented compatibility decision.
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
- Route external commands through the controlled runner. Executables and
  working directories must be explicit canonical absolute paths; child
  environments start from the approved locale baseline and exact allowlists,
  output is bounded and strict UTF-8, and protected values/paths are redacted
  before results or diagnostics cross the boundary. Never add ambient `PATH`,
  proxy, tool-argument, workspace, config-discovery, callback/plugin, or
  input-variable families without a reviewed registry entry and threat tests.
- Do not log or format an environment, command, model, state object, or exception
  that may include credentials without passing it through tested redaction.
- Keep provider-specific concepts behind provider adapters. OCI is initially the
  only accepted provider; do not advertise AWS/GCP support before it exists.
- Public errors and exit codes must be stable, useful, and mapped at the CLI
  boundary. Preserve causes for protected diagnostic logs.
- Maintain compatibility with the documented Python and dependency support
  matrix once one is established. Do not silently raise minimum versions.
- The current application lock is a POSIX `flock`/`O_NOFOLLOW` implementation
  and must fail closed on platforms without those primitives. Do not claim
  cross-platform lock support until an equally race-safe implementation and
  contention tests exist.
- Local `show` reads take an exclusive flock on the existing canonical cluster
  directory and, when present, the diagnostic lock file. The read lock
  must never create, truncate, or rewrite a filesystem entry; shared-read
  locking remains deferred.

## Configuration and secrets

- Secret values come only from environment variables. Do not add secret
  command-line flags, plaintext config keys, persistent credential files,
  checked-in credentials, generated password files, or secret defaults.
- If a downstream tool requires a credential file, create it from the
  environment as an owner-only, short-lived runtime file, redact its path where
  useful, and remove it reliably.
- Non-secret precedence must remain explicit and tested. Unless documentation is
  deliberately updated, use CLI over environment over config/default.
- The supported non-secret config format is strict TOML schema
  `deploy-scylla-vms.config/v2` with one `[cluster]` table. Keep it read-only,
  native-typed, canonical-path validated, and limited to the approved desired
  fields; state roots, actions, selectors, confirmations, and secrets are not
  config fields.
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
- Provider adapters are offline typed transformations unless an explicit
  provider discovery interface is invoked. The OCI adapter consumes validated
  caller-supplied capability facts; never describe syntactic input validation as
  proof of account resource existence, shape capacity, or live availability.
- Config/desired schema v2 requires explicit per-deployed-role OCI image
  OS/version filters and,
  for managed networking, an RFC 1918 VCN CIDR plus non-overlapping per-zone
  private subnet CIDRs. Public subnet CIDRs/IPs are jump-host-only and require
  explicit enablement and operator CIDRs. Reject v1 records rather than
  defaulting either decision.
- Persist deterministic provider input only as
  `deploy-scylla-vms.tfvars/v1` at
  `<cluster-root>/terraform/work/cluster.auto.tfvars.json`, using the matching
  held lock and generation/digest guards. Public SSH key material is allowed only
  after strict regular-file/link/ownership/permission/size/OpenSSH validation;
  private keys and arbitrary Terraform arguments remain forbidden.
- Stage only immutable approved source bundles with exact `oci-root/vN` versions
  and per-file hashes. The `deploy-scylla-vms.terraform-source/v1` record belongs
  at `<cluster-root>/terraform/source.json`; reject tamper, unexpected files,
  unsafe links, downgrade, and source changes with active Terraform
  state/backend/provider data. A non-planning-ready bundle must never reach plan.
- Keep the single active packaged OCI root at
  `scylla_vms/terraform/bundles/oci_root/`. Bundle versions are logical immutable
  identities in source records, not physical directory suffixes. During
  unreleased development, update the stable root and advance its logical bundle
  ID when compatibility requires it; retain an old physical root only for a
  reviewed migration that genuinely needs parallel source.
- Packaged `oci-root/v3` includes reviewed image selection, managed/existing
  networking, role NSGs, stable-ID compute, Block Volume/local-NVMe branches,
  and the strict host manifest. It constrains OCI provider `~>9.1.0` and is
  planning-ready. Existing-network routing suitability is a
  later preflight fact; Terraform must not modify user-owned network resources.
  Public ingress is jump-host SSH from explicit operator CIDRs only; private SSH
  uses jump NSG references, and no client CQL ingress exists without a separately
  versioned explicit selector.
  Regenerate its tracked `.terraform.lock.hcl` only with Terraform tooling.
  Validate source with an isolated `TF_DATA_DIR`, `terraform init
  -backend=false`, `terraform fmt -check`, `terraform validate`, and
  `terraform providers schema -json`; never plan this partial bundle.
- Preserve application-level and Terraform/backend locking. Never disable
  locking to make a test or operation pass.
- Detect state or backend metadata outside the canonical path before
  initialization. Stop on conflicts; never silently create replacement state,
  migrate, import, move, or delete unexpected state.
- Explicit state initialization requires the selected state root's direct
  parent to exist; it creates only the root and documented children. Preserve
  the POSIX descriptor-relative/no-follow race defenses and the exact `0700`
  directory/`0600` file policy.
- Consume `terraform output -json` through a versioned, strict schema. Do not
  parse human output.
- Persist validated Terraform observations only as
  `deploy-scylla-vms.observed/v1` at
  `<cluster-root>/terraform/observed.json`. Preserve cluster/schema/source/
  capture-time/generation/digest binding, use the matching held cluster lock,
  and never persist raw Terraform output, arguments, environment, or diagnostics.
- The implemented Terraform CLI contract is stable
  `>=1.5.0,<2.0.0`; reject prereleases and probe only with
  `terraform version -json`. Every cluster command uses the internal anchored
  builder and already-held matching application lock. Keep destroy absent.
  Exact saved-plan apply construction is available only to the reviewed durable
  execution owner and remains absent from the general Terraform service and all
  CLI paths.
- The internal immutable
 `deploy-scylla-vms.terraform-plan-checkpoint/v1` belongs only at
 `<cluster-root>/terraform/plans/<operation-uuid>.terraform-plan.json`. Create
 it under the matching non-read-only operation lock from an existing canonical
 saved plan, bounded `terraform show -json`, exact initial PLAN journal, current
 desired/tfvars/source, supported toolchain, and canonical local-state identity.
 Persist only versions, generations, counts, classes, state serial, and digests;
 never plan/state values, resource addresses, raw lineage, or paths. Treat any
 refresh drift, deletion, or replacement explicitly and bind complete,
 destructive, replacement, deletion, and drift scopes by digest. Revalidation
 may accept a later PLAN/CONFIRM journal only when unique PLAN evidence names
 the exact checkpoint digest. This record never authorizes or constructs apply:
 keep its redacted review at authorization `not-collected` and execution
 `unavailable`; later reviewed contracts own authorization, safeguarding, and
 exact-plan execution.
- The internal deploy-only PLAN composer accepts canonical state-root/cluster
  identity, one operation UUID, and the matching already-held deploy lock. It
  must load the immutable Terraform checkpoint canonically, revalidate its exact
  generation-1 journal preimage plus current desired/tfvars/source/backend/
  state/toolchain and saved-plan bindings, and append only one
  `PLAN/validated` checkpoint-digest event to the existing common v1 journal.
  Preserve checkpoint-first ordering: a failed journal append leaves a
  recoverable checkpoint-only prefix, exact generation-2 re-entry performs no
  write, and every conflicting, duplicate, advanced, terminal, execution,
  stale, tampered, unsafe, or ambiguous state fails closed without overwrite,
  deletion, or rollback. Keep
  `deploy-scylla-vms.terraform-deploy-plan-composition-report/v1` independently
  versioned and limited to created/reused state, schemas/digests, bounded
  counts/classes/booleans/scope digests, and explicit uncollected/not-started/
  unavailable states. This layer must never accept plan content, journal
  payloads, paths, commands, variables, environments, authorization, phase, or
  status; collect confirmation; approve a plan; create apply commands; back up
  state; invoke Terraform; cross a destructive boundary; or enable deploy.
- The internal deploy-only PLAN orchestrator accepts canonical state-root/
  cluster identity, one operation UUID, the matching already-held deploy lock,
  the controlled runner, and explicit validated Terraform executable/toolchain
  dependencies. It must load the exact generation-1 journal and current desired/
  tfvars/source/work-tree/backend/state bindings before effects, run only the
  existing anchored detailed-plan and saved-plan-show builders, and write plan
  output only to
  `<cluster-root>/terraform/plans/<operation-uuid>.tfplan.staging`. Require
  detailed exit 0/2 to agree with strict complete show JSON, revalidate every
  pre-run binding and unchanged plan bytes, atomically promote to
  `<operation-uuid>.tfplan`, then create the immutable checkpoint before
  invoking the existing composer. Exact saved-plan-only recovery may rerun show
  only when bound files have not changed after planning; exact checkpoint and
  composed prefixes must avoid plan/show calls. Reject staged/temporary/
  duplicate artifacts, drift, unsafe links/modes/sizes, process uncertainty,
  and conflicting saved plans/checkpoints without deletion or automatic
  replanning. Keep
  `deploy-scylla-vms.terraform-deploy-plan-orchestration-report/v1` limited to
  stage states, schemas/digests, bounded counts/classes/booleans/scope digests,
  toolchain version, and retry/recovery flags. This layer must not accept caller
  paths, commands, arguments, variables, environment, or plan JSON; collect
  authorization; back up state; build/run apply or destroy; capture outputs;
  reconcile; finalize; or add CLI/public wiring.
- The internal exact-plan apply authorizer accepts canonical state-root/cluster
  identity, one operation UUID, the matching already-held deploy lock, and an
  already-normalized typed proof. It must canonically revalidate the exact
  generation-2 composed PLAN journal, immutable checkpoint/review/saved-plan,
  current desired/tfvars/source/backend/state/toolchain bindings, and every
  address-free count/scope digest before persistence. Derive the effective class
  only from the plan: no-change creates no authorization; create/update requires
  ordinary interactive or permitted `--yes` approval; replacement/deletion
  escalates to destructive and requires separate `--allow-destructive` plus
  exact destructive/replacement/deletion count/scope proof. Review-required
  refresh drift needs separate interactive review, conflict drift is refused,
  and absent state permits only drift-free create-only plans. Persist immutable
  owner-only `deploy-scylla-vms.terraform-apply-authorization/v1` only at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-authorization.json`.
  Keep narrow wipe/recreation/reprovision/decommission proofs separate. Exact
  re-entry may reuse; every changed proof or binding fails closed. Keep the
  common v1 journal unchanged at PLAN, execution not-started/unavailable,
  authorization unconsumed, and CLI/public deploy wiring disabled; apply
  command construction and invocation belong only to the later execution owner.
- The internal immutable pre-apply state safeguard accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. It must canonically revalidate the exact composed PLAN,
  checkpoint/review/saved-plan, unconsumed authorization, desired/tfvars/source/
  backend/state/toolchain bindings, and apply-required classification. No-change
  plans create neither authorization nor safeguard artifacts. Existing local
  state must be a bounded singly linked owner-only regular `0600` file whose
  minimal top-level identity and full byte digest match the reviewed prior
  state; copy its exact bytes with descriptor-relative/no-follow replacement
  checks to immutable
  `<cluster-root>/terraform/backups/<operation-uuid>.terraform.tfstate`.
  Verified absent initial state requires drift-free create-only semantics,
  continued canonical absence, and clean unexpected-state checks, and creates
  no fake state or backup. Persist independently versioned
  `deploy-scylla-vms.terraform-state-safeguard/v1` only at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-state-safeguard.json`.
  Validate before backup, and publish the record only after backup durability.
  Exact backup-only recovery and exact record reuse are allowed; conflicting,
  missing, changed, or unsafe artifacts fail closed without overwrite, deletion,
  pruning, automatic restore, or retry. Keep journal at PLAN, authorization
  unconsumed, execution unavailable/not-started, destructive boundary uncrossed,
  and CLI/public wiring disabled. This safeguard must not construct or invoke
  the later exact-plan apply command.
- The internal durable exact-plan apply execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and explicit validated Terraform executable/
  toolchain dependencies. It must load and revalidate the exact composed PLAN
  journal, immutable checkpoint/review/saved plan, unconsumed authorization,
  safeguard and backup-or-absence proof, current desired/tfvars/source/work tree/
  backend/pre-apply state, unexpected-state checks, toolchain, classification,
  and proof digests immediately before intent and again before consumption.
  Apply-required exact saved plans only; refuse no-change/not-required plans,
  missing/stale/consumed authorization or safeguard, unsupported/conflict drift,
  replay, another execution record, and every destructive-proof mismatch before
  invoking the runner. The sole apply builder is exact saved-plan
  `terraform apply -input=false -no-color -lock=true -lock-timeout=30s <plan>`;
  retain canonical executable/`-chdir`/cwd, controlled `TF_DATA_DIR` and plugin
  cache, local backend, default timeout/output bound, and no auto-approve,
  destroy, target, replace, refresh-only, parallelism, variables, workspace,
  proxy, CLI config, or ambient Terraform arguments.
  Persist owner-only
  `deploy-scylla-vms.terraform-apply-execution/v1` only at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-execution.json`.
  Bind journal, checkpoint/review/composition, authorization/proof, safeguard/
  backup-or-absence, desired/tfvars/source/backend/pre-apply state/toolchain,
  exact command, and classification through schemas/generations/digests without
  protected paths, raw command/environment/plan/state/output, addresses,
  provider IDs, diagnostics, credentials, or secrets. Order validation,
  retry-safe `prepared`, the legal common-journal EXECUTE intent transition,
  durable `started` authorization consumption, exactly one runner call, then
  bounded terminal process outcome. Exact prepared prefixes may resume after
  full revalidation. Once `started` is durable, any crash, timeout,
  interruption, nonzero exit, invalid/oversized output, malformed result,
  runner error, or terminal-write failure is uncertain, manual-recovery-required,
  verification-required, and never automatically retried, rolled back, restored,
  deleted, replanned, or reapplied. Re-entry from started or later makes zero
  runner calls. Exit zero is only
  `process-succeeded-verification-pending`; keep the common journal nonterminal
  at EXECUTE/VERIFY. This owner must not parse apply output, capture Terraform
  output, reconcile state/observations/inventory, finalize, run destroy, expose
  a direct service bypass, or add CLI/public deploy wiring.
- The internal post-apply verification/reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, a controlled runner, and explicit validated
  Terraform executable/toolchain dependencies. It must canonically revalidate
  the exact `process-succeeded-verification-pending` execution plus journal,
  saved plan/checkpoint/review/composition, consumed authorization, safeguard/
  backup-or-absence, desired/tfvars/source/work tree/backend/toolchain, and
  canonical local state before effects. Refuse every no-change, not-started,
  uncertain, failed, recovery-required, stale, changed, unsafe, or ambiguous
  prefix before invoking the runner. Verify post-apply state through bounded
  owner-only no-follow reads and descriptor/path stability: existing state
  preserves reviewed lineage and advances serial/digest; absent initial state
  permits only a valid new lineage and positive serial for a drift-free
  create-only plan. Run only the existing anchored
  `terraform output -json -no-color -state=<canonical-state>` command with the
  controlled local-backend environment. Strictly parse and reconcile complete
  host/image/network/topology/storage output against current desired and
  provider input, then persist only guarded `deploy-scylla-vms.observed/v1`.
  Persist immutable owner-only
  `deploy-scylla-vms.terraform-apply-verification/v1` only at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-verification.json`,
  binding pre/post state, execution, journal, plan, authorization, safeguard,
  desired/tfvars/source/backend/toolchain, output/observation, and bounded
  reconciliation evidence through schemas/generations/digests without raw
  state/output, addresses, provider IDs, commands, environment, paths,
  diagnostics, credentials, or secrets. Order validation/state proof, legal
  nonterminal VERIFY transition, output, parse/reconcile, observation, then
  verification companion. Bind the prior observation artifact or exact absence
  in the VERIFY transition. Exact observation-only recovery may avoid an
  output rerun only when the current observation differs from that bound
  baseline and exactly belongs to the unchanged VERIFY prefix; exact completed
  re-entry is zero-process. Every ambiguity is
  manual review and never reruns apply. Keep the common journal
  `IN_PROGRESS/VERIFY`; this proves only infrastructure observation
  reconciliation and must not create inventory/trust, scan SSH, run Ansible,
  finalize deploy, or add CLI/public wiring.
- The internal verified-apply inventory owner accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. It must load and revalidate the exact successful apply
  verification, process-success execution and saved-plan checkpoint, unchanged
  `IN_PROGRESS/VERIFY` journal, and current metadata/desired/tfvars/source/
  observation bindings before any write. Generate only through the existing
  deterministic validated observation-to-inventory transformation and persist
  only owner-only `deploy-scylla-vms.inventory/v1` at
  `<cluster-root>/ansible/inventory.yml`. Persist the independently versioned
  immutable
  `deploy-scylla-vms.terraform-apply-inventory/v1` companion only at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-inventory.json`,
  binding the exact verifier and inventory plus address-free counts and
  topology/group/route digests. Exact inventory may be reused; an unchanged
  model from a newer verified observation may advance inventory generation
  through the existing guards. Existing inventory identity, membership,
  topology, endpoint, or route conflicts and SSH-trust identity/key/endpoint/
  route conflicts fail closed. Semantically matching trust that is no longer
  generation-current is `stale` and requires revalidation, never silent trust
  rewrite. Order validation, in-memory generation, inventory persistence/reuse,
  then companion persistence; an exact inventory-only prefix may recover
  without rewrite. Keep the common journal at `IN_PROGRESS/VERIFY`.
  This owner must not render controller/SSH files, scan or confirm host keys,
  run Terraform/SSH/Ansible, collect machine readiness, finalize deploy, or add
  CLI/public wiring.
- The internal verified-inventory SSH-trust owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, existing typed direct/routed candidate collections, and
  normalized per-key explicit-confirmation or independently supplied matching
  SHA-256 fingerprint proofs. It must canonically revalidate the exact
  successful apply verifier/inventory companion, unchanged
  `IN_PROGRESS/VERIFY` journal, and current metadata/desired/tfvars/source/
  observation/inventory/trust/derivative bindings before writes. Derive every
  endpoint, port, identity, and route from canonical inventory; accept only
  Ed25519 and NIST P-256 ECDSA keys with exact candidate identity, source,
  endpoint, fingerprint, and routed-jump provenance.
  Establish direct jump trust first and report private trust pending. Accept
  routed private candidates only on a later call when exact jump trust was
  current at collection and remains current; never create an untrusted jump and
  routed private chain simultaneously. Complete stale trust may advance only
  through exact per-key revalidation proofs without candidates. Changed keys,
  identities, membership, endpoints, or routes require the separate replacement
  workflow and must never be overwritten.
  Persist only guarded owner-only `deploy-scylla-vms.ssh-trust/v1` and
  deterministic `known_hosts`/`ssh_config`. Once every inventory host is
  current, persist independently versioned immutable
  `deploy-scylla-vms.terraform-apply-trust/v1` only at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-trust.json`,
  binding operation/journal/verifier/inventory companion/source/observation/
  inventory/trust/proof and derivative digests plus bounded host counts and an
  address-free route digest. Reports and companions must omit addresses,
  provider IDs, keys, fingerprints, routes, file content, protected paths, and
  secrets. Order validation, trust/derivative persistence or exact recovery,
  then complete companion persistence. Keep the common journal at
  `IN_PROGRESS/VERIFY`. This owner must not collect candidates, scan hosts, run
  Terraform/SSH/Ansible, validate machine inventory/readiness, finalize deploy,
  or add public/CLI wiring.
- The internal operation-bound deploy-readiness owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling
  `ansible-playbook`/`ansible-inventory` pair with an explicit supported
  Ansible toolchain dependency. It must canonically revalidate the exact
  successful apply verification/inventory/trust companions, unchanged
  `IN_PROGRESS/VERIFY` journal, and current metadata/desired/source/
  observation/inventory/trust and deterministic trust derivatives before any
  process call. Missing, staged, stale, incomplete, conflicting, or unsafe
  trust must fail before the runner.
  Render or exact-reuse only canonical owner-only
  `<cluster-root>/ansible/ansible.cfg` through the existing deterministic
  renderer, retaining strict host-key checking, exact inventory/SSH-config/
  known-hosts bindings, and controller home/temp/cache/control/log data below
  the cluster root. Probe both exact executables through the controlled runner
  and require matching stable ansible-core `>=2.17.0,<2.21.0` plus exact
  dependency identity. Run only controller-local
  `ansible-inventory --inventory <canonical-inventory> --list`; never run a
  playbook or contact a host. Strictly parse normalized output and prove exact
  static-inventory host/group/hostvar, role/zone/datacenter/rack, SSH user/port,
  endpoint, ProxyJump, and derivative parity. Raw machine JSON and protected
  values must never be persisted, logged, or projected.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.terraform-apply-readiness/v1` only at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-readiness.json`.
  Bind operation/journal/apply companions, current source/observation/
  inventory/trust, config, executable/toolchain and machine evidence,
  readiness, bounded counts, and address-free topology/group/route digests.
  Keep remote connectivity, health, and playbook execution explicitly
  `not-performed`. Exact current companion re-entry may make zero process
  calls; companion-write failure may repeat only the safe local validation.
  Keep the common journal at `IN_PROGRESS/VERIFY`. This owner must not run
  inventory preflight, connectivity/evidence playbooks, SSH/keyscan,
  Terraform, remote Ansible, deployment, finalization, or add CLI/public
  wiring.
- The internal deploy-specific Ansible PLAN/context-binding owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must not reuse the generic Ansible binding,
  whose checkpoint semantics require PLAN while this stage remains at
  `IN_PROGRESS/VERIFY`. Canonically revalidate the exact successful apply
  verification/inventory/trust/readiness chain plus current metadata/desired/
  Terraform source/observation/inventory/trust derivatives, rendered config,
  packaged Ansible source, and catalog before any write.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-context/v1` then
  `deploy-scylla-vms.ansible-deploy-plan/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-context.json` and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-plan.json`.
  Build both in memory first. Exact records may be reused and an exact
  context-only prefix may recover; plan-without-context, generic companions,
  drift, conflicts, advanced state, unsafe paths, and ambiguous duplicates fail
  closed without overwrite, deletion, rollback, or journal transition.
  Expand exactly the registry `deploy` sequence and conditions. Derive role
  targets only from sorted stable logical IDs, expand single-host policy per
  target, and bind classification, limit, serial, check mode, allowlisted
  variable names/digest, exact playbook source hash, command-intent digest, and
  explicit blocker enums. The nested intent schema may contain only explicit
  safe `unmodeled`, `not-collected`, and `not-performed` states; never accept or
  persist arbitrary variables, addresses, provider IDs, hostvars, routes, keys,
  fingerprints, device paths, commands, environments, credentials, secrets,
  tokens, passwords, prompts, or raw evidence.
  Keep every step blocked or not-performed while public orchestration, remote
  connectivity/host evidence, storage/wipe/bootstrap/health/quorum/backup/
  capacity, Manager/backend, monitoring, package/configuration, and required
  authorizations remain unavailable. Local readiness alone is not execution
  readiness. The strict report retains only schemas/digests, bounded playbook/
  role/step/target/status counts, blocker enums/digest, and catalog/source/
  readiness bindings. This owner must not invoke a runner, run any playbook,
  collect authorization or evidence, start services, create execution or
  finalization records, change the journal, or add CLI/public deploy wiring.
- The internal deploy-prerequisite execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling
  `ansible-playbook`/`ansible-inventory` pair with its explicit supported
  toolchain dependency. It must canonically revalidate the complete verified
  Terraform/apply/inventory/trust/readiness chain, rendered controller files,
  packaged source/catalog, unchanged `IN_PROGRESS/VERIFY` journal, and the
  exact immutable deploy context/plan before every effect. Identify only
  mapping steps one and two: controller-local `inventory-preflight` and initial
  complete-host-set `connectivity-check`. Derive their sorted stable-ID limits
  and fixed SSH-only variables internally; destination probes, caller limits,
  variables, commands, environment, paths, plans, steps, results, and evidence
  are forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-prerequisite-execution/v1` at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-prerequisite-execution.json`.
  Record each exact step as `started` before its runner call. A started crash,
  timeout, interruption, malformed/non-UTF-8/oversized result, failed or
  unreachable semantic result, or post-invocation persistence failure is
  manual-recovery-required and permanently forbids automatic retry. Only an
  exact succeeded first-step prefix may continue to connectivity.
  Parse strict inventory-preflight and connectivity evidence; exit zero alone
  is insufficient. Require exact command/target identity and complete unique
  host membership. Persist semantic evidence before terminal step success in
  independently versioned immutable-prefix
  `deploy-scylla-vms.ansible-deploy-prerequisite-evidence/v1` at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-prerequisite-evidence.json`.
  Retain only schemas, statuses, bounded counts, stable-ID set/route and
  command/result/evidence digests, and provenance bindings; omit addresses,
  provider IDs, routes, keys, fingerprints, raw output/events, commands,
  variables, environment, paths, credentials, and secrets. Exact complete
  re-entry must make zero process calls. Full success proves only inventory
  parity and initial SSH connectivity as `deploy-prerequisites-ready`; it does
  not rewrite the immutable blocked plan, collect host/OS/storage/package/
  configuration/bootstrap/health/Manager/monitoring evidence, authorize or run
  mutating playbooks, finalize deploy, change the common journal, or add
  CLI/public wiring.
- The internal deploy-plan reconciliation owner accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. It must canonically reload the unchanged
  `IN_PROGRESS/VERIFY` journal, full verified Terraform/apply/inventory/trust/
  readiness chain, immutable deploy context/original plan, completed
  prerequisite execution/evidence, packaged source, and catalog. Recompute the
  exact original 21-position mapping and require every expanded sequence,
  condition, classification, target, policy, variable, source, and command
  digest to remain unchanged; catalog, source, mapping, or provenance drift
  requires a new operation and explicit re-plan.
  Persist only immutable owner-only
  `deploy-scylla-vms.ansible-deploy-effective-plan/v1` at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-effective-plan.json`.
  Bind the exact journal/context/original-plan/readiness/prerequisite/source/
  catalog artifacts and a deterministic effective-plan digest. Mark only the
  exact inventory preflight and initial connectivity steps `succeeded` with
  their semantic evidence. Inactive conditions remain `not-performed`; later
  read-only facts remain `not-performed` until their ordered gates are
  independently satisfied; every mutating, sensitive, or destructive step
  remains blocked with class-specific and authorization blockers. Never rewrite
  the original context, plan, execution, or evidence.
  Build and validate fully in memory before atomic no-follow persistence; exact
  reuse is zero-write and every conflict fails closed. The report may retain
  only schemas/digests, bounded status counts, safe next-eligible playbook names
  and stable-ID counts, blocker enums/digest, and journal status/phase. This
  owner must not create authorization or execution intent, invoke a runner or
  toolchain, advance the journal, finalize deploy, or add CLI/public wiring.
- The internal deploy pre-mutation host-evidence owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling
  `ansible-playbook`/`ansible-inventory` pair with its explicit supported
  toolchain dependency. It must canonically reload and revalidate the unchanged
  `IN_PROGRESS/VERIFY` journal, full verified Terraform/apply/inventory/trust/
  readiness chain, immutable deploy context/original/effective plans,
  successful prerequisite execution/evidence, rendered controller/trust files,
  packaged source, and catalog before every effect. Require the effective plan
  to preserve only initial inventory preflight/connectivity success; the final
  mapped `evidence-collect` remains `not-performed`.
  Define a separate digest-bound `pre-mutation-host-evidence` checkpoint.
  Partition the complete sorted stable-ID inventory deterministically by role
  and invoke only the existing read-only `evidence-collect` source through the
  anchored service. Derive limits and the fixed bounded evidence timeout
  internally; caller playbooks, limits, variables, commands, environment,
  paths, evidence, and results are forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-pre-mutation-host-evidence-execution/v1` at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-pre-mutation-host-evidence-execution.json`
  and immutable-prefix
  `deploy-scylla-vms.ansible-deploy-pre-mutation-host-evidence/v1` at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-pre-mutation-host-evidence.json`.
  Record each batch as `started` before its runner call. Parse the exact host
  schema and require one unique role-applicable result per selected stable ID;
  exit zero alone is insufficient. Persist semantic evidence before terminal
  success.
  Retain only stable ID/role, OS/version/architecture, truthful reboot evidence
  status, bounded CPU/memory and mount/device availability/counts, hashed
  mount/device-set evidence, allowlisted service states, role-health status/
  digest, bounded blockers, and exact provenance/command/result/evidence
  digests. Omit addresses, provider IDs, raw device paths/serials, routes,
  keys/fingerprints, raw output/events/logs, commands, variables, environment,
  paths, credentials, and secrets. Unsupported platforms are bounded blockers.
  A crash, timeout, interruption, malformed/non-UTF-8/oversized result,
  missing/extra/duplicate/wrong-role/protected evidence, nonzero/failed/
  unreachable evidence, or post-invocation persistence failure is manual-
  recovery-required and permanently forbids automatic retry. Only an exact
  succeeded role prefix may continue; exact complete re-entry is zero-process.
  Keep the effective plan and common journal byte-for-byte unchanged. This
  owner must not authorize base OS/storage/package work, run storage discovery,
  write diagnostics evidence, persist raw evidence, reconcile the effective
  plan, finalize deploy, or add CLI/public wiring.
- The internal pre-mutation host-evidence reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must canonically reload and revalidate the
  unchanged `IN_PROGRESS/VERIFY` journal, complete verified Terraform/apply/
  inventory/trust/readiness chain, immutable context/original plan, successful
  prerequisite records, prior effective plan, complete exact pre-mutation
  execution/evidence, source, and catalog. Recompute and preserve every mapping,
  sequence, condition, class, target, policy, variable, source, and command
  identity; missing/extra/duplicate/reordered/wrong-role, uncertain, stale,
  conflicting, or drifted evidence fails closed before persistence.
  Evaluate only exact Ubuntu 24.04/architecture, reboot, allowlisted service,
  CPU/memory, root-mount, and role-applicable device evidence. Unknown stays
  unknown; never infer package readiness, storage ownership/wipe safety, cluster
  emptiness, health, replication, quorum, backup, or capacity safety.
  Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-host-evidence-reconciliation/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-host-evidence-reconciliation.json`.
  Bind the prior effective plan and distinct checkpoint artifacts. Preserve the
  original inventory/connectivity successes and final mapped
  `evidence-collect` as `not-performed`; checkpoint evidence belongs only in
  reconciliation metadata. A next-ordered role-scoped `base-os` step with all
  applicable gates passed may be only
  `evidence-ready-authorization-required`, retaining authorization, execution,
  and public-workflow blockers; no step is eligible or executable. Every later
  storage/package/configuration/bootstrap/health/Manager/monitoring gate stays
  blocked or not performed. Exact reuse is zero-write and every conflict fails
  closed without overwrite, deletion, rollback, or journal transition.
  Reports retain only schemas/digests, step and gate counts, grouped next
  authorization-required playbook/role/stable-ID counts, blocker enums/digest,
  and journal status/phase. This owner must not create authorization or
  mutating intent, invoke a runner/toolchain, finalize, or add CLI/public wiring.
- The internal deploy `base-os` authorization owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, and an already-normalized ordinary approval proof. It must
  canonically reload the complete verified Terraform/apply/inventory/trust/
  readiness, deploy context/original/effective plan, prerequisite, pre-mutation
  host-evidence, reconciliation, source, catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal chain before persistence. Derive every
  authorizable step and stable-ID target only from exact
  `evidence-ready-authorization-required` reconciliation statuses; only active
  mapping-position-three `base-os` instances with mutating classification are
  valid. Missing, extra, wrong, later-stage, blocked, uncertain, or drifted
  scope fails closed.
  Require ordinary interactive approval or PLAN-permitted `--yes`; reject
  destructive flags/scope proof and never collect wipe, replacement,
  decommission, bootstrap, or free-form consent. Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-base-os-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-base-os-authorization.json`.
  Bind exact operation/journal, context/plans/reconciliations/evidence/readiness/
  source/catalog and step sequence/playbook/source/command/target/variable
  digests, plus stable-ID count/set digest and normalized proof enum/boolean/
  digest. Exact reuse is zero-write; changed proof or provenance requires a new
  plan and operation. Authorization remains unconsumed, execution unavailable,
  all non-authorized steps unchanged, and the journal byte-for-byte at VERIFY.
  This owner must not create execution intent or records, invoke a runner or
  toolchain, mutate step status, finalize, or add CLI/public deploy wiring.
- The internal deploy `base-os` execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling
  `ansible-playbook`/`ansible-inventory` pair with its explicit supported
  toolchain dependency. It must canonically reload the complete verified
  Terraform/apply/inventory/trust/readiness, deploy context/original/effective/
  host-evidence-reconciled plan, prerequisite, pre-mutation host-evidence,
  immutable base-OS authorization, source, catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal chain before every effect.
  Derive each mapping-position-three `base-os` instance, stable-ID limit, typed
  Ubuntu 24.04/image-architecture variables, guest-architecture parity, and
  anchored command only from those immutable records and canonical current
  state. Caller steps,
  playbooks, targets, limits, variables, paths, commands, environment,
  authorization, results, and loop bounds are forbidden. Execute exact scopes
  only in deterministic authorization order, one controlled call per durably
  recorded attempt.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-base-os-execution/v1` at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-base-os-execution.json`
  and immutable-prefix
  `deploy-scylla-vms.ansible-deploy-base-os-evidence/v1` at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-base-os-evidence.json`.
  Record `prepared` only after full validation, then record `started` immediately
  before the runner call. The started record consumes the immutable
  authorization without rewriting it. Strictly parse the exact base-OS result,
  require complete unique selected-host membership and platform/provenance
  parity, persist address-free semantic evidence, then persist terminal outcome;
  exit zero alone is insufficient.
  Once started, crash, timeout, interruption, failed/unreachable/malformed/
  non-UTF-8/oversized result, state drift, or post-call persistence failure is
  manual-recovery-required and permanently forbids automatic retry. Exact
  prepared recovery is allowed only because no invocation could have occurred;
  exact completed re-entry is zero-process. Keep the effective plan and common
  journal byte-for-byte unchanged at VERIFY. This owner must not reboot, roll
  back packages, restore images, run another playbook, reconcile later steps,
  finalize, or add CLI/public wiring.
- The internal post-`base-os` result reconciliation owner accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. It must canonically reload and revalidate the complete verified
  Terraform/apply/inventory/trust/readiness, deploy context/original/effective/
  host-evidence-reconciled plan, prerequisite, pre-mutation host-evidence,
  immutable base-OS authorization/execution/evidence, source, catalog, and
  unchanged `IN_PROGRESS/VERIFY` journal chain before persistence. Caller
  results, statuses, steps, targets, variables, commands, paths, runners,
  executables, and toolchains are forbidden.
  Require exact terminal-success execution and complete unique semantic evidence
  for every authorized stable ID. Prepared, started, failed, uncertain, manual-
  recovery, missing, extra, duplicate, wrong-host, mixed, stale, or provenance-
  drifted state fails closed. Recompute the complete deploy mapping and preserve
  every sequence, condition, classification, target, policy, variable, source,
  command, and original-step digest.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-base-os-reconciliation/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-base-os-reconciliation.json`.
  Exact executed `base-os` instances become evidence-bound `succeeded`; changed
  and already-current remain bounded evidence. If any host requires reboot,
  record `reboot-required` and `reboot-handling-not-performed`, keep reboot
  handling `not-performed`, and block every later active step. Never reboot,
  reconnect, authorize, or execute another step. Without reboot, evaluate only
  the exact next ordered gate that strict base-OS evidence and independently
  current canonical evidence can prove. A mutating next step may become only
  `evidence-ready-authorization-required`; a read-only next step may become
  `eligible`. Never leapfrog. Unexecuted base-OS scopes and all later storage/
  package/configuration/bootstrap/health/Manager/monitoring/final-evidence
  gates remain blocked or not performed. Do not promote pre-mutation facts
  across the mutation boundary except fields explicitly superseded by the
  strict base-OS result; unknown remains unknown.
  Build and validate fully in memory before atomic no-follow persistence. Exact
  reuse is zero-write; conflicts never overwrite, delete, roll back, or adapt
  the operation. Reports retain only schemas/digests, bounded step/change/
  reboot/next-step/stable-ID counts and digests, blocker enums/digest, and
  journal status/phase. This owner must not create authorization or execution
  intent, invoke a runner/toolchain, transition the journal, reboot, finalize,
  or add CLI/public wiring.
- The internal deploy reboot planning/authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and an optional already-normalized ordinary
  approval proof. It must canonically reload and revalidate the complete
  verified Terraform/apply/inventory/trust/readiness, deploy context/original/
  effective/host-evidence/base-OS-reconciled plans, prerequisite/connectivity,
  pre-mutation evidence, immutable base-OS authorization/execution/semantic
  evidence, source, catalog, and unchanged `IN_PROGRESS/VERIFY` journal chain.
  Caller targets, order, commands, variables, paths, classification, reboot
  policy, free-form text, runners, executables, and toolchains are forbidden.
  Derive reboot targets only from exact successful base-OS evidence marked
  `reboot-required`; require exact reconciliation count/scope parity. No-reboot
  state returns strict `not-required`, accepts no proof, creates no reboot
  artifacts, and leaves the no-reboot next-step status unchanged.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-reboot-plan/v1` then
  `deploy-scylla-vms.ansible-deploy-reboot-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-reboot-plan.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-reboot-authorization.json`.
  Preserve exact base-OS execution order with stable-ID tie-breaking, serial
  one, role batches, and current inventory/trust/route/connectivity bindings.
  Refuse incomplete connectivity, unknown roles/order, missing jump
  dependencies, or a routed host ordered before its selected jump dependency
  with stable blockers and no authorization.
  Every target must require future post-reboot reconnect, exact identity/trust
  revalidation, machine evidence, and base-OS reboot-clear verification before
  the next target. Reboot handling within deploy is mutating and requires
  ordinary interactive or PLAN-permitted `--yes` approval; destructive flags
  and scope proof are inapplicable. Exact records may be reused and an exact
  plan-only prefix may recover authorization; every changed proof, scope,
  order, evidence, or provenance fails closed without overwrite, deletion,
  rollback, or adaptation. Reports retain only schemas/digests, bounded target/
  role counts, order/role-batch/serial/checkpoint policy, approval method/state,
  blocker enums/digest, and journal status/phase. Keep addresses, provider IDs,
  routes, keys, commands, variables, environment, paths, raw evidence, prompts,
  credentials, and secrets absent. Authorization remains unconsumed, execution
  unavailable, reconnect not performed, and the journal/step reconciliations
  unchanged. This owner must not invoke a process, reboot/reconnect a host,
  create execution records, advance later deploy stages, finalize, or add
  CLI/public wiring.
- The internal deploy reboot execution owner accepts only canonical state-root/
  cluster identity, one operation UUID, the matching already-held deploy lock,
  a controlled runner, and an exact validated sibling Ansible executable pair
  with its explicit supported toolchain dependency. It must canonically reload
  and revalidate the complete verified Terraform/apply/inventory/trust/
  readiness, deploy context/original/effective/host-evidence/base-OS-
  reconciled plans, prerequisite/connectivity and pre-mutation evidence,
  immutable base-OS authorization/execution/evidence, exact reboot plan and
  unconsumed authorization, source, catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal before every effect. Caller targets, order,
  limits, variables, playbooks, paths, commands, environment, results, and
  retry controls are forbidden.
  Execute only the immutable plan order, exact one target at a time. Persist
  generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-reboot-execution/v1` at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-reboot-execution.json`.
  Record `prepared` before invocation and `started` immediately before the
  controlled call; the first started record consumes authorization for the
  exact whole ordered scope. A strict succeeded prefix may continue only after
  complete semantic post-reboot evidence for every preceding target.
  Invoke only the hash-checked `deploy-reboot` source: Ubuntu 24.04,
  exact-one-target, serial-one/fatal, check-mode-refused, fixed role-specific
  inactive service gates, in-memory hashed pre-boot identity, and bounded
  `ansible.builtin.reboot` with no shell or arbitrary command. Strictly parse
  only `deploy-scylla-vms.ansible-deploy-reboot/v1` and require exact target,
  request, command, source, OS/version/architecture, reconnect, changed boot
  identity, current trust, machine evidence, post-reboot service safety, and
  absent `/var/run/reboot-required`; exit zero alone is insufficient.
  Persist independently versioned immutable-prefix owner-only
  `deploy-scylla-vms.ansible-deploy-reboot-evidence/v1` at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-reboot-evidence.json`
  before terminal success. Bind operation/journal, plan/authorization,
  base-OS/connectivity/inventory/trust/readiness/source/catalog/toolchain,
  ordered targets, and per-target plan/variable/command/request/result/evidence
  digests. Retain only stable ID, bounded role/OS/architecture/status,
  reconnect/boot-change/identity/trust/machine/service/reboot-clear booleans,
  bounded elapsed time, and digests. Omit raw boot IDs, addresses, provider
  IDs, routes, keys, facts, commands, environment, output, credentials, and
  secrets.
  Once started, crash, timeout, interruption, unreachable/nonzero execution,
  malformed/non-UTF-8/oversized output, host-key/identity/OS/architecture/
  reconnect/boot-change/service/reboot-clear mismatch, post-call drift, or
  persistence failure is uncertain, manual-recovery-required, and permanently
  no-retry. Never reboot that target again automatically, skip it, continue,
  roll back, or rewrite trust. Exact complete re-entry is zero-process.
  Complete success proves only reboot-scope success and post-reboot evidence
  readiness. Keep the common journal and deploy-step reconciliations unchanged
  at `IN_PROGRESS/VERIFY`; do not rerun general connectivity/evidence, reconcile
  later steps, authorize next work, run Terraform/OCI, finalize, or add
  CLI/public wiring.
- The internal post-reboot deploy-plan reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must canonically reload and revalidate the
  unchanged `IN_PROGRESS/VERIFY` journal; full verified Terraform/apply/
  inventory/trust/readiness, deploy context/original/effective/host-evidence/
  base-OS-reconciled plans, prerequisite/connectivity, pre-mutation evidence,
  immutable base-OS authorization/execution/evidence, source, and catalog chain.
  Caller statuses, targets, order, results, steps, variables, commands, paths,
  runners, executables, and toolchains are forbidden.
  The no-reboot branch requires absent reboot plan/authorization/execution/
  evidence, persists `not-required`, and preserves only the already-proven next
  gate. The reboot-required branch must reconstruct the exact reboot plan,
  authorization, scope, variables, command intent, and binding; require complete
  ordered terminal-success attempts and evidence for every target, consumed
  authorization, no uncertainty/recovery, and true pre-service/reboot/
  reconnect/boot-change/identity/trust/machine/post-service/reboot-clear gates.
  Missing, partial, extra, duplicate, reordered, wrong-target, started, failed,
  uncertain, stale, drifted, or mismatched state fails before persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-reboot-reconciliation/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-reboot-reconciliation.json`.
  Recompute the exact deploy mapping and preserve every prior sequence,
  condition, classification, target, policy, variable, source, command, and
  step identity. Base-OS successes remain evidence-bound. Complete reboot proof
  clears only the exact reboot blockers; only immediate
  `jump-host-configure` may become
  `evidence-ready-authorization-required`, never execution-eligible. Treat
  pre-reboot connectivity/host evidence only as bound provenance except for
  fields explicitly superseded by strict post-reboot evidence. Keep all other
  active scopes and later stages blocked/not-performed.
  Build and validate fully in memory before atomic no-follow persistence. Exact
  reuse is zero-write; conflicts never overwrite, delete, roll back, or adapt.
  Reports retain only schemas/digests, bounded branch/status and reboot/
  reconnect/reboot-clear/next-authorization counts, target set/order digests,
  blocker enums/digest, and unchanged journal status/phase. Omit boot IDs,
  addresses, provider IDs, routes, keys, commands, variables, environment,
  paths, raw evidence, credentials, and secrets. This owner must not create
  authorization/execution intent, invoke a runner/toolchain, change the journal
  or earlier companions, reboot, finalize, or add CLI/public wiring.
- The internal deploy `jump-host-configure` authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and an already-normalized ordinary approval proof.
  It must canonically reload and revalidate the complete verified Terraform/
  apply/inventory/trust/readiness, deploy context/original/effective/host-
  evidence/base-OS/post-reboot reconciled plans, prerequisite/pre-mutation/
  base-OS/reboot authorization/execution/evidence, source, catalog, and
  unchanged `IN_PROGRESS/VERIFY` journal chain before persistence.
  Derive every authorizable step and stable-ID target only from exact
  post-reboot `evidence-ready-authorization-required` statuses. Only active
  mutating mapping-position-four `jump-host-configure` instances against
  canonical jump-host inventory identities are valid. Missing, extra, wrong-
  role, wrong-step, broader, narrower, stale, drifted, or uncertain scope fails
  closed.
  Require ordinary interactive approval or PLAN-permitted `--yes`; reject
  destructive flags/scope proof and never collect storage wipe, replacement,
  decommission, bootstrap, or free-form consent. Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-authorization/v1` only
  at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-jump-host-configure-authorization.json`.
  Bind exact operation/journal, context/plans/reconciliations/evidence/
  inventory/trust/readiness/source/catalog and step sequence/playbook/source/
  command/target/variable digests, plus stable-ID count/set, mutating
  classification, and normalized proof method/digest. Exact reuse is zero-write;
  changed proof, scope, or provenance requires a new plan and operation.
  Authorization remains unconsumed, execution unavailable, every step status
  unchanged, and the journal byte-for-byte at VERIFY. Reports retain only
  schemas/digests, bounded counts, method/state/classification,
  non-authorized-blocker digest, and journal state. This owner must not create
  execution intent or records, invoke a runner/toolchain, mutate step status,
  finalize, or add CLI/public deploy wiring.
- The internal deploy `jump-host-configure` execution owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, a controlled runner, and an exact validated sibling
  Ansible executable pair with its explicit supported toolchain dependency. It
  must canonically reload and revalidate the complete authorization and
  post-reboot chain, current observation/inventory/trust/readiness/connectivity,
  source/catalog, rendered controller files, and unchanged
  `IN_PROGRESS/VERIFY` journal before every effect.
  Derive the exact ordered mapping-position-four scopes, one jump stable ID per
  call, role-level configuration authorization, PermitOpen routes, rendered
  policy, typed variable payload, and anchored command internally. Caller
  steps, playbooks, targets, limits, variables, paths, commands, environment,
  authorization, results, and loop controls are forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-jump-host-configure-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-jump-host-configure-evidence.json`.
  Record retry-safe `prepared`, then durable `started` immediately before the
  controlled call; `started` consumes the immutable whole-scope authorization
  without rewriting it. Require the exact strict result, stable ID, canonical
  provenance, policy/route/configuration digests, successful validation, and
  change/reload consistency before semantic evidence and terminal success.
  Exit zero alone is insufficient.
  Once started, crash, timeout, interruption, unreachable/nonzero execution,
  malformed/non-UTF-8/oversized output, identity/trust/policy/route/config
  mismatch, validation/reload failure, post-call drift, or persistence failure
  is manual-recovery-required and permanently forbids automatic retry, skip, or
  continuation. Internal role restore behavior is not retry proof; v1 evidence
  records restoration as not required on success or not proven on failure.
  Exact prepared recovery is allowed before invocation; an exact succeeded
  prefix may continue and complete re-entry is zero-process. Keep the
  authorization, post-reboot reconciliation, every step status, and common
  journal byte-for-byte unchanged at VERIFY. This owner must not rewrite trust,
  bypass SSH checking, rerun connectivity, execute another playbook, reconcile
  the next plan, finalize, or add CLI/public deploy wiring.
- The internal post-`jump-host-configure` result reconciliation owner accepts
  only canonical state-root/cluster identity, one operation UUID, and the
  matching already-held deploy lock. It must canonically reload and revalidate
  the unchanged `IN_PROGRESS/VERIFY` journal; full verified Terraform/apply/
  inventory/trust/readiness, deploy context/original/effective/host-evidence/
  base-OS/post-reboot reconciled plans, prerequisite/connectivity and
  pre-mutation evidence, base-OS/reboot/jump-host authorization/execution/
  semantic evidence, current observation/inventory/trust/readiness, source,
  and catalog chain. Caller results, statuses, steps, targets, variables,
  commands, paths, runners, executables, and toolchains are forbidden.
  Require exact terminal-success execution, consumed execution authorization,
  complete unique semantic evidence for every authorized jump stable ID,
  current policy/PermitOpen/configuration/route/source/command/variable
  bindings, successful sshd validation, reload success exactly when changed,
  and unambiguous restore-not-required evidence. Prepared, started, failed,
  uncertain, manual-recovery, missing, extra, duplicate, wrong-target, stale,
  validation/reload/restore-ambiguous, or provenance-drifted state fails before
  persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-jump-host-configure-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-jump-host-configure-reconciliation.json`.
  Recompute the exact documented deploy mapping and preserve every sequence,
  condition, classification, target, policy, variable, source, command, and
  original/prior-step digest. Exact executed jump instances become
  evidence-bound `succeeded`, retaining bounded changed/no-change evidence.
  Derive the first remaining active mapping: only its fully proven scopes may
  become read-only `eligible` or mutating
  `evidence-ready-authorization-required`. Current mapping advances only
  final-routes connectivity; non-jump `base-os` may advance only when every
  earlier mapping is inactive and unaffected host evidence remains current.
  Never promote jump-host pre-mutation facts across this mutation except exact
  result evidence. Keep storage/package/configuration/bootstrap/health/
  Manager/monitoring/final-evidence and public stages blocked/not-performed.
  Build and validate fully in memory before atomic no-follow persistence.
  Exact reuse is zero-write; conflicts never overwrite, delete, roll back, or
  adapt. Reports retain only schemas/digests, bounded jump/result/status and
  next playbook/role/target counts/set digests, blocker enums/digest, and
  unchanged journal state; omit addresses, provider IDs, routes, configuration
  content, keys, commands, variable values, environment, paths, raw evidence,
  credentials, and secrets. This owner must not authorize or execute the next
  gate, invoke a runner/toolchain, rewrite trust, change the journal, finalize,
  or add CLI/public deploy wiring.
- The internal deploy final-routes connectivity owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically reload and revalidate the complete verified Terraform/apply/
  inventory/trust/readiness, deploy context/original/effective/host-evidence/
  base-OS/post-reboot/post-jump-host reconciled plans, prerequisite/initial
  connectivity and pre-mutation evidence, base-OS/reboot/jump-host
  authorization/execution/evidence, current observation/inventory/trust/
  readiness derivatives, source, catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal before every effect.
  Derive the exact eligible final-routes `connectivity-check`, sorted jump
  stable-ID limit, and destination role/port pairs only from immutable mapping
  and canonical inventory-assigned routes. Accept only documented role/port
  allowlists and RFC 1918 destination identities. Caller playbooks, steps,
  targets, limits, destination hosts/roles/ports, variables, tags, commands,
  paths, environments, results, statuses, and retry controls are forbidden.
  Never permit public destinations, arbitrary scanning, unassigned routes, or
  private-target SSH.
  Invoke only the hash-checked connectivity source through the anchored
  controlled service with canonical config/inventory/cwd, strict host-key
  checking, exact stable-ID limits and typed probes, bounded timeout/output,
  strict UTF-8/redaction, and no arbitrary callbacks/plugins/environment.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-final-routes-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-final-routes-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-final-routes-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-final-routes-evidence.json`.
  Record `started` before the sole runner call. Require exact source/result/
  step/command identity, one unique SSH outcome per selected jump, one unique
  result per requested role/port pair, no missing/extra/duplicate/wrong host or
  pair, and all outcomes successful; exit zero alone is insufficient.
  Evidence may retain only stable jump IDs, destination roles/ports, bounded
  statuses/counts, and provenance/set/request/result/evidence digests.
  Addresses, provider IDs, routes, keys, raw output, commands, variable values,
  environment, paths, credentials, and secrets must remain absent.
  Once started, crash, timeout, interruption, unreachable/nonzero execution,
  malformed/non-UTF-8/oversized output, semantic mismatch, post-call drift, or
  persistence failure is uncertain, manual-recovery-required, and permanently
  no-retry. Exact complete re-entry is zero-process; conflicting prefixes fail
  closed. Keep the common journal and prior reconciliations unchanged.
- The internal post-final-routes reconciliation owner accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. It must reload and revalidate the same complete chain and require
  exact terminal-success execution plus current complete semantic evidence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-final-routes-reconciliation/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-final-routes-reconciliation.json`.
  Mark only the exact final-routes connectivity instance evidence-bound
  `succeeded`, recompute the complete deploy mapping, and evaluate only the
  immediate next active gate. Non-jump `base-os` may become
  `evidence-ready-authorization-required` only when all unaffected independent
  evidence remains current. Never hard-code or leapfrog a later gate.
  Exact reuse is zero-write and conflicts fail closed. Reports retain only
  schemas/digests, bounded execution/jump/pair/step/next-gate counts and set
  digests, blocker enums, retry/recovery truth, and unchanged journal
  status/phase. This slice must not create authorization, execute a mutation,
  invoke Terraform/OCI/SSH scanners, alter the journal or prior companions,
  finalize deploy, or add CLI/public wiring.
- The internal post-final-routes non-jump `base-os` authorization owner accepts
  only canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and an already-normalized ordinary approval proof.
  It must canonically reload and revalidate the complete verified Terraform/
  apply/inventory/trust/readiness, deploy context/original/effective/
  host-evidence/base-OS/post-reboot/post-jump-host/post-final-routes
  reconciliation, prerequisite/pre-mutation/base-OS/reboot/jump-host/
  final-routes execution and semantic-evidence, current inventory/trust/
  readiness, source, catalog, and unchanged `IN_PROGRESS/VERIFY` journal chain
  before persistence.
  Derive only active mutating mapping-position-six `base-os` with condition
  `non-jump-managed-hosts` and exact status
  `evidence-ready-authorization-required`. Its sorted stable-ID scope must
  equal the canonical non-jump managed inventory set, remain disjoint from the
  earlier immutable jump-scope base-OS authorization, and retain exact
  sequence/source/command/variable/target, final-routes-evidence, and
  pre-mutation-host-evidence identities. Jump, earlier-authorized, extra,
  missing, wrong, inactive, non-ready, broadened, ambiguous, uncertain, or
  drifted scope fails closed. Caller steps, targets, roles, limits, variables,
  commands, paths, classification, scope, prompts, and free-form text are
  forbidden.
  Require ordinary interactive approval or PLAN-permitted `cli-yes`; reject
  denied/malformed proof, destructive flags/scope, and narrow consent as
  inapplicable. Neither proof bypasses identity, route/connectivity, trust,
  readiness, host-evidence, reboot, ordering, or drift gates.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-base-os-authorization.json`.
  This path and scope must remain distinct from the earlier
  `<operation-uuid>.ansible-deploy-base-os-authorization.json`, which is never
  overwritten or reused. Bind stage/scope, exact step and target digests,
  final-routes execution/evidence/reconciliation, host evidence, and full
  upstream provenance. Exact reuse is zero-write; changed proof, scope, or
  state requires a new operation. Authorization remains unconsumed until a
  later durable started execution.
  Reports retain only schemas/digests, stage/scope, approval method/state,
  playbook/role/target counts and set digests, blocker digest,
  `consumed=false`, execution unavailable, and journal status/phase. This owner
  must not invoke a runner/toolchain, create execution intent or records,
  mutate step status, change the journal, handle reboot, finalize, or add
  CLI/public deploy wiring.
- The internal post-final-routes non-jump `base-os` execution owner accepts
  only canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, a controlled runner, and an exact validated sibling
  Ansible executable pair with its explicit supported toolchain dependency. It
  must canonically reload and revalidate the complete chain through exact
  terminal final-routes reconciliation, current pre-mutation host evidence,
  current inventory/trust/readiness/connectivity, immutable distinct non-jump
  authorization, packaged source/catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal before every effect.
  Derive only active mapping-position-six `base-os` with condition
  `non-jump-managed-hosts`, its sorted complete non-jump managed stable-ID
  scope, typed Ubuntu 24.04/image-architecture variables, guest-architecture
  parity, and anchored command. Refuse jump or earlier jump-scope overlap,
  missing/extra/non-ready hosts, OS/architecture/reboot/service/capacity/route
  blockers, stale or consumed authorization, uncertain history, and provenance
  drift before invocation. Caller steps, playbooks, targets, limits, variables,
  paths, commands, environments, authorization, results, and loop controls are
  forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-base-os-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-base-os-evidence.json`.
  Record retry-safe `prepared`, then durable `started` immediately before the
  controlled call; that first started record consumes the whole distinct
  authorization without rewriting it. Invoke only the hash-checked `base-os`
  source with canonical controller files, strict host-key checking, exact
  stable-ID limit and variables, serial-one policy, bounded timeout/output,
  strict UTF-8/redaction, and no arbitrary tags/plugins/callbacks/environment.
  Require strict complete unique result membership, Ubuntu/architecture and
  provenance parity, and coherent applied/changed/reboot-required/prerequisite/
  timesync evidence; exit zero alone is insufficient. Persist only stable IDs,
  bounded OS/version/architecture/status values, applied/changed/reboot flags,
  prerequisite/timesync statuses, and digests.
  Once started, crash, timeout, interruption, failed/unreachable/nonzero,
  malformed/non-UTF-8/oversized output, semantic mismatch, post-call drift, or
  persistence failure is manual-recovery-required and permanently forbids
  retry, replay, skip, continuation, reboot, or rollback. An exact prepared
  prefix may resume before invocation; an exact succeeded prefix may continue
  only in immutable order, and complete re-entry is zero-process. Keep the
  authorization, prior artifacts, step reconciliations, and common journal
  byte-for-byte unchanged at VERIFY. This owner must not reconcile the result,
  handle reboot, authorize or execute another stage, finalize, or add CLI/public
  deploy wiring.
- The internal post-non-jump-`base-os` result reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must canonically reload and revalidate the full
  verified Terraform/apply/inventory/trust/readiness and deploy chain through
  exact terminal non-jump authorization/execution/evidence, current source and
  catalog, and the unchanged `IN_PROGRESS/VERIFY` journal. Caller results,
  statuses, steps, targets, paths, runners, executables, and toolchains are
  forbidden.
  Require exact terminal success, consumed execution authorization, and
  complete unique semantic evidence for every authorized non-jump stable ID.
  Prepared, started, failed, uncertain, manual-recovery, missing, extra,
  duplicate, wrong-scope, malformed, stale, or provenance-drifted state fails
  before persistence. Recompute the exact mapping and persist immutable
  owner-only
  `deploy-scylla-vms.ansible-deploy-post-non-jump-base-os-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-non-jump-base-os-reconciliation.json`.
  Mark only exact mapping-position-six non-jump `base-os` instances
  `succeeded` with distinct result-evidence binding. Preserve changed and
  already-current counts. If any host requires reboot, record
  `reboot-required` and `reboot-handling-not-performed`, block every later
  active step, and never reuse the earlier jump-scope reboot artifacts. Without
  reboot, derive the first remaining active mapping and advance only fully
  proven immediate scopes: read-only work may become `eligible`, while
  mutating work may become only `evidence-ready-authorization-required`.
  Current mapping permits only Scylla `storage-discover`; no later gate may
  leapfrog it. Pre-mutation fields superseded by base-OS execution are not
  promoted beyond the strict result.
  Build fully in memory before atomic owner-only no-follow persistence. Exact
  reuse is zero-write and conflicts fail closed. Reports retain only schemas,
  digests, bounded success/change/reboot/next-gate/playbook/role/target counts,
  blocker enums, and unchanged journal state. This owner must not authorize,
  execute, invoke a runner, create reboot artifacts, mutate storage, change the
  journal, finalize, or add CLI/public wiring.
- The internal non-jump deploy reboot planning/authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and an optional already-normalized ordinary
  approval proof. It must canonically reload and revalidate the full verified
  Terraform/apply/inventory/trust/readiness and deploy chain through exact
  post-non-jump-base-OS reconciliation. Derive only successful non-jump
  base-OS targets whose strict semantic evidence says `reboot_required`;
  require exact reconciliation count/scope parity and never reuse or overwrite
  the earlier jump-scope reboot plan or authorization.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-plan/v1` then
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-reboot-plan.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-reboot-authorization.json`.
  Preserve exact non-jump base-OS execution order with stable-ID tie-breaking,
  serial one, configured jump-route dependencies, and current final-routes
  connectivity. Bind inventory, trust, readiness, final-routes, non-jump
  execution/evidence/reconciliation, source, catalog, and unchanged journal.
  Every target requires future reconnect, identity/trust revalidation, machine
  evidence, role-service safety, and reboot-clear verification before the next
  target. Stable incomplete-connectivity, route-dependency, and order blockers
  prevent authorization.
  A ready mutating plan requires ordinary interactive or PLAN-permitted
  `cli-yes` proof; destructive proof is inapplicable. Persist the plan before
  authorization, allow exact plan-only recovery and exact zero-write reuse,
  and fail every changed scope, order, proof, route, evidence, or provenance
  without overwrite, deletion, rollback, or adaptation. If no reboot is
  required, accept no proof, create no artifact, return strict `not-required`,
  and preserve the independently reconciled `storage-discover` branch.
  Reports retain only schemas/digests, bounded counts, blocker enums, and
  future-gate booleans. Keep addresses, provider IDs, routes, keys, commands,
  variables, environment, paths, raw evidence, credentials, and secrets
  absent. Authorization remains unconsumed, execution/reconnect unavailable or
  not-performed, and the common journal and all prior artifacts unchanged.
  This owner must not invoke a process, reboot or reconnect a host, create
  execution records, reconcile post-reboot state, run storage discovery,
  finalize deploy, or add CLI/public wiring.
- The internal non-jump deploy reboot execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically reload and revalidate the complete verified Terraform/apply/
  inventory/trust/readiness and deploy chain through exact non-jump reboot
  plan/authorization and post-non-jump-base-OS reconciliation before every
  effect. Caller targets, order, limits, variables, playbooks, paths, commands,
  environments, results, and retry controls are forbidden.
  Execute only the immutable non-jump plan order, exact one target at a time.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-reboot-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-reboot-evidence.json`.
  Record `prepared` before invocation and `started` immediately before the
  controlled call; the first started record consumes the whole distinct
  non-jump authorization without rewriting it. A strict succeeded prefix may
  continue only to the next immutable target.
  Invoke only the hash-checked `deploy-reboot` source and require exact target,
  request, command, source, OS/version/architecture, reconnect, changed boot
  identity, current trust, machine evidence, pre/post service safety, and
  reboot-clear semantics. Exit zero alone is insufficient. Evidence must omit
  raw boot IDs, addresses, provider IDs, routes, keys, commands, environments,
  output, credentials, and secrets.
  Once started, a crash, timeout, interruption, unreachable/nonzero execution,
  malformed/non-UTF-8/oversized output, semantic mismatch, post-call drift, or
  persistence failure is uncertain, manual-recovery-required, and permanently
  no-retry. Never reboot that target again automatically, skip it, continue,
  roll back, or rewrite trust. Exact complete re-entry is zero-process. Keep
  the common journal and every prior artifact unchanged at
  `IN_PROGRESS/VERIFY`; do not reconcile post-reboot state, run storage
  discovery, authorize later work, finalize, or add CLI/public wiring.
- The internal post-non-jump-reboot deploy-plan reconciliation owner accepts
  only canonical state-root/cluster identity, one operation UUID, and the
  matching already-held deploy lock. It must canonically reload and revalidate
  the full verified Terraform/apply/inventory/trust/readiness and deploy chain
  through exact post-non-jump-base-OS reconciliation and the distinct non-jump
  reboot plan/authorization/execution/evidence family.
  The no-reboot branch requires exact zero reboot candidates and absence of all
  distinct non-jump reboot artifacts. The reboot-required branch requires the
  exact recomputed unblocked plan and authorization, complete ordered terminal
  success, consumed execution authorization, no uncertainty/recovery, and true
  pre-service/reboot/reconnect/boot-change/identity/trust/machine/post-service/
  reboot-clear gates for every target. Missing, partial, extra, duplicate,
  reordered, wrong-target, prepared, started, failed, uncertain, stale,
  drifted, or mismatched state fails before persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-non-jump-reboot-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-non-jump-reboot-reconciliation.json`.
  Recompute the complete deploy mapping and preserve every prior sequence,
  condition, classification, target, policy, variable, source, command, and
  step identity. No-reboot preserves the independently derived next gate.
  Complete reboot proof clears only the reboot blockers and may advance only
  the first remaining active mapping: read-only work may become `eligible`,
  while mutating work may become only
  `evidence-ready-authorization-required`. Current mapping permits only Scylla
  `storage-discover`; no later gate may leapfrog it.
  Build fully in memory before atomic owner-only no-follow persistence. Exact
  reuse is zero-write and conflicts fail closed. Reports retain only schemas,
  digests, bounded branch/target/success/gate/next-step counts, safe summaries,
  blocker enums, and unchanged journal state. This owner must not invoke a
  runner or external tool, authorize or execute another stage, mutate any
  prior artifact or journal, finalize, or add CLI/public deploy wiring.
- The internal deploy storage-discovery execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically reload and revalidate the full verified Terraform/apply/
  inventory/trust/readiness and deploy chain through exact
  post-non-jump-reboot reconciliation before every effect. Derive only the
  exact eligible mapping-position-seven Scylla `storage-discover` instance,
  sorted complete Scylla stable-ID scope, catalog source, explicit limit,
  serial-five policy, runtime variables, and anchored command from immutable
  canonical records. Caller steps, playbooks, targets, limits, variables,
  paths, commands, environments, results, statuses, and retry controls are
  forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-storage-discovery-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-storage-discovery-evidence/v2` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-discovery-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-discovery-evidence.json`.
  Record durable `started` before the sole controlled call. Require strict
  storage-discovery schema/provenance and exact complete unique host/device
  membership; exit zero alone is insufficient. Retain only stable IDs,
  bounded statuses/counts/sizes/booleans, and hashed device/signature/
  ownership/topology identities. Omit raw device paths/serials, addresses,
  provider IDs, routes, keys, raw output, commands, variable values,
  environments, paths, credentials, and secrets.
  Once started, crash, timeout, interruption, nonzero/unreachable execution,
  malformed/non-UTF-8/oversized output, semantic mismatch, post-call drift, or
  persistence failure is uncertain, manual-recovery-required, and permanently
  no-retry. Never skip or continue after uncertainty. Exact complete re-entry
  is zero-process and conflicting prefixes fail closed.
  The internal post-storage-discovery reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must reload and revalidate the same complete
  chain and require exact terminal-success execution plus current complete
  semantic evidence. Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-storage-discovery-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-storage-discovery-reconciliation.json`.
  Mark only the exact storage-discovery instance evidence-bound `succeeded`,
  recompute the complete deploy mapping, and evaluate only the immediate next
  active gate. Current mapping may make read-only Scylla
  `storage-preflight` eligible when exact evidence gates pass; never create
  storage mutation authorization or leapfrog a later gate. Exact reuse is
  zero-write and conflicts fail closed. Keep the common journal and all prior
  artifacts byte-for-byte unchanged. These owners must not execute storage
  preflight/prepare/postcheck, authorize or mutate storage, finalize, or add
  CLI/public deploy wiring.
- The internal deploy storage-preflight execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically reload and revalidate the full verified Terraform/apply/
  inventory/trust/readiness and deploy chain through exact
  post-storage-discovery reconciliation before every effect. Derive only the
  exact eligible mapping-position-eight Scylla `storage-preflight` instance,
  sorted complete Scylla stable-ID scope, typed desired-policy/manifest/
  discovery projection, catalog source, explicit limit, serial-five/check-mode
  policy, and anchored command from immutable canonical records. Caller steps,
  playbooks, targets, limits, variables, paths, commands, environments,
  results, statuses, and retry controls are forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-storage-preflight-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-storage-preflight-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-preflight-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-preflight-evidence.json`.
  Record durable `started` before the sole controlled call. Require exact
  schema/provenance and complete unique host/result membership; exit zero alone
  is insufficient. Retain only stable IDs, bounded backend/layout/capacity,
  exact desired/manifest/discovery digests, disposition/action enums, hashed
  device sets, blocker/status digests, wipe booleans, and preparation-intent
  digests. Omit addresses, provider IDs, raw device paths/serials, routes,
  keys, raw output, commands, variables, environments, paths, credentials,
  and secrets.
  Once started, crash, timeout, interruption, nonzero/unreachable execution,
  malformed/non-UTF-8/oversized output, semantic mismatch, post-call drift, or
  persistence failure is uncertain, manual-recovery-required, and permanently
  no-retry. Never skip or continue after uncertainty. Exact complete re-entry
  is zero-process and conflicting prefixes fail closed.
  The internal post-storage-preflight reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must reload and revalidate the same complete
  chain and require exact terminal-success execution plus current complete
  semantic evidence. Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-storage-preflight-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-storage-preflight-reconciliation.json`.
  Mark only the exact storage-preflight instance evidence-bound `succeeded`.
  Blocked hosts remain blocked. `owned-noop` is not required and must never be
  rewritten or authorized. Derive immediate storage-prepare authorization
  scope only for exact `prepare-required` hosts, binding each stable ID,
  disposition, device-set, and preparation-intent digest. Keep wipe-required
  target and scope digests separate for later explicit wipe consent. Exact
  reuse is zero-write and conflicts fail closed. Keep the common journal and
  all prior artifacts byte-for-byte unchanged. These owners must not create or
  collect preparation/wipe authorization, execute storage preparation/
  postcheck, mutate storage, leapfrog a later gate, finalize, or add CLI/public
  deploy wiring.
- The internal deploy `storage-prepare` authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, one normalized typed general proof, and an optional
  normalized typed wipe proof. It must canonically reload the full verified
  Terraform/apply/inventory/trust/readiness and deploy chain through exact
  post-storage-preflight reconciliation before persistence. Derive only exact
  `prepare-required` hosts and their stable-ID/action/disposition/device-set/
  preparation-intent digests. `owned-noop` and `blocked` hosts are never in
  scope.
  Every scope is destructive and requires ordinary interactive or PLAN-
  permitted `cli-yes` approval plus separate `--allow-destructive` and exact
  address-free destructive scope proof; `cli-yes` alone never authorizes it.
  Exact wipe consent is a distinct proof required only for the complete
  wipe-required subset. Missing, extra, narrower, broader, non-wipe, or
  mismatched proof fails closed.
  Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-storage-prepare-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-prepare-authorization.json`.
  Bind the exact plan/evidence/inventory/trust/readiness/source/catalog/journal
  chain, per-host preparation scopes, separate preparation/wipe counts and
  scope digests, and independently versioned general/wipe proof decisions.
  Exact reuse is zero-write; conflicts require a new operation. Authorization
  remains unconsumed, execution unavailable, and the common journal and all
  prior artifacts byte-for-byte unchanged. Reports must remain address-,
  provider-, device-path-, command-, variable-, path-, prompt-, credential-,
  and secret-free. This owner must not invoke a runner/toolchain, create
  execution intent or evidence, mutate storage, execute postcheck, advance a
  later gate, finalize, or add CLI/public deploy wiring.
- The internal deploy `storage-prepare` execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically reload and revalidate the complete verified Terraform/apply/
  inventory/trust/readiness and deploy chain through exact immutable
  post-storage-preflight reconciliation and unconsumed storage preparation
  authorization before every effect. Derive only exact ordered
  `prepare-required` scopes with their action/disposition/device-set/
  preparation-intent/source/variable/command/provenance digests; never execute
  `owned-noop` or blocked storage.
  Invoke only hash-checked catalog `storage-prepare`, exact one stable ID at a
  time, serial one, check mode refused, with internally constructed controlled
  variables. Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-storage-prepare-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-storage-prepare-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-prepare-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-prepare-evidence.json`.
  Record retry-safe `prepared`, then durable `started` immediately before each
  controlled call. The first started attempt consumes the exact general
  authorization; consume wipe proof only at an exact wipe-required target
  boundary. Strict succeeded prefixes may continue only in immutable order.
  Require the role result to prove immediate device revalidation, exact action,
  disposition, device set, preparation intent and provenance, wipe application,
  mutation boundary, first irreversible step, completed state, and post-action
  verification. Exit zero alone is insufficient. Evidence retains only stable
  IDs, bounded action/disposition/status/count values, hashed device/provenance
  identities, wipe/mutation/recovery booleans, and digests. Omit addresses,
  provider IDs, device paths/serials, raw output, commands, variables,
  environments, protected paths, credentials, and secrets.
  Once started, crash, timeout, interruption, nonzero/unreachable execution,
  malformed/non-UTF-8/oversized output, semantic mismatch, state drift, or
  post-call persistence failure is manual-recovery-required and permanently
  forbids retry, replay, skip, continuation, automatic rollback, or wipe rerun.
  Exact complete re-entry is zero-process. Keep the common journal and all
  prior artifacts byte-for-byte unchanged at `IN_PROGRESS/VERIFY`. This owner
  must not reconcile preparation, execute storage postcheck, advance a later
  gate, finalize, or add CLI/public deploy wiring.
- The internal post-storage-prepare reconciliation owner accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must canonically reload and revalidate the
  complete verified Terraform/apply/inventory/trust/readiness and deploy chain
  through exact preflight reconciliation, authorization, preparation execution,
  and semantic evidence. Every `prepare-required` target must have exact
  ordered terminal success, consumed general authorization, consumed wipe proof
  where applicable, matching action/disposition/device-set/preparation-intent/
  provenance, and no recovery uncertainty. Missing, partial, extra, started,
  failed, uncertain, mismatched, stale, or drifted state fails before
  persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-storage-prepare-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-storage-prepare-reconciliation.json`.
  Mark exact prepare-required steps evidence-bound `succeeded`; preserve
  `owned-noop` as current and explicitly not mutated; keep blocked storage
  blocked. Derive only exact current Scylla scope for the immediate read-only
  `storage-postcheck` gate. Never promote blocked storage, claim an owned no-op
  was prepared, authorize another mutation, or leapfrog to package
  installation. Exact reuse is zero-write and conflicts fail closed. Reports
  retain only schemas, digests, bounded outcome/authorization/wipe/step counts,
  blocker enums, and unchanged journal state. This owner must not invoke a
  process, execute postcheck, mutate storage, change the journal, finalize, or
  add CLI/public deploy wiring.
- The internal deploy storage-postcheck execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically reload and revalidate the complete verified Terraform/apply/
  inventory/trust/readiness and deploy chain through exact post-storage-prepare
  reconciliation before every effect. Derive only the exact eligible
  mapping-position-ten Scylla `storage-postcheck` instances and sorted scopes,
  preserving exact preparation-success and current `owned-noop` provenance.
  Invoke only the hash-checked source, exact one stable ID at a time, serial
  one, check mode enabled, with internally derived variables and anchored
  commands.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-storage-postcheck-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-storage-postcheck-evidence/v1` only under
  `<cluster-root>/operations/`. Record durable `started` before each controlled
  call. Require exact complete unique result membership and every device,
  RAID, XFS, UUID, fstab, mount, capacity, permission, marker, and provenance
  check to pass; exit zero alone is insufficient. Retain only hashed device
  identities, bounded statuses/counts/capacities, and provenance/blocker
  digests. Omit addresses, provider IDs, device paths/serials, filesystem UUIDs,
  commands, variables, environments, raw output, credentials, and secrets.
  Once started, crash, timeout, interruption, nonzero/unreachable execution,
  malformed/non-UTF-8/oversized output, semantic mismatch, post-call drift, or
  persistence failure is uncertain, manual-recovery-required, and permanently
  no-retry.
  The internal post-storage-postcheck reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  held deploy lock. It must reload the same complete chain and require exact
  terminal-success execution plus current complete semantic evidence. Persist
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-storage-postcheck-reconciliation/v1`
  only under `<cluster-root>/operations/`. Mark only exact postcheck instances
  evidence-bound `succeeded` and advance only immediate active
  `scylla-install` scopes to `evidence-ready-authorization-required`. Never
  infer Scylla health or leapfrog a later gate. Exact reuse is zero-write and
  conflicts fail closed. Keep the common journal and all prior artifacts
  byte-for-byte unchanged. These owners must not authorize or execute package
  installation, mutate storage, finalize, or add CLI/public deploy wiring.
- The internal deploy `scylla-install` authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and one normalized ordinary approval proof. It
  must canonically reload and revalidate the complete verified Terraform/apply/
  inventory/trust/readiness and deploy chain through exact
  post-storage-postcheck reconciliation before persistence. Derive only active
  mapping-position-eleven `scylla-install` instances whose exact status is
  `evidence-ready-authorization-required`, their current Scylla stable-ID
  targets, and the catalog/source-bound ScyllaDB 2026.2 package set,
  repository-definition digest, and authenticated signing-key provenance.
  Caller targets, versions, packages, repositories, keys, variables, commands,
  paths, scopes, prompts, and free-form text are forbidden. Require ordinary
  interactive approval or PLAN-permitted `cli-yes`; reject destructive flags,
  destructive-scope proof, and narrow consent as inapplicable. Persist
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-install-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-install-authorization.json`.
  Exact reuse is zero-write; changed proof, scope, provenance, or state requires
  a new operation. Authorization remains unconsumed, execution unavailable, and
  the common journal and all prior artifacts byte-for-byte unchanged. Reports
  retain only schemas, digests, bounded counts, approval method/state,
  classification, and journal state. This owner must not invoke a runner,
  install packages, create execution intent or records, mutate step status,
  finalize, or add CLI/public deploy wiring.
- The internal deploy `scylla-install` execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically reload and revalidate the complete verified Terraform/apply/
  inventory/trust/readiness and deploy chain through exact post-storage-
  postcheck reconciliation, immutable unconsumed Scylla-install authorization,
  current base-OS evidence, packaged source/catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal before every effect.
  Derive only the exact authorized mapping-position-eleven `scylla-install`
  scopes, one stable ID per call, typed Ubuntu 24.04/image-architecture and
  exact 2026.2 package/repository/signing-key variables, and anchored command
  identity from immutable canonical records. Caller steps, playbooks, targets,
  limits, variables, paths, commands, environments, authorization, results,
  and loop controls are forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-install-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-scylla-install-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-install-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-install-evidence.json`.
  Record retry-safe `prepared`, then durable `started` immediately before the
  controlled call; the first started attempt consumes the whole immutable
  authorization without rewriting it. Require strict complete exact target,
  package, repository, signing-key, source, command, and provenance identity,
  successful installed/no-change status, a masked and inactive
  `scylla-server`, and explicit absence of configuration, storage, tuning,
  Manager, and service-start actions. Exit zero alone is insufficient.
  Once started, crash, timeout, interruption, failed/unreachable/nonzero,
  malformed/non-UTF-8/oversized output, semantic mismatch, post-call drift, or
  persistence failure is manual-recovery-required and permanently forbids
  retry, replay, skip, continuation, or rollback. An exact prepared prefix may
  resume before invocation, an exact succeeded prefix may continue only in
  immutable order, and complete re-entry is zero-process. Keep the
  authorization, prior artifacts, step reconciliations, and common journal
  byte-for-byte unchanged at VERIFY. This owner must not reconcile the result,
  authorize or execute another stage, finalize, or add CLI/public deploy
  wiring.
- The internal post-`scylla-install` reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must canonically reload and revalidate the full
  verified Terraform/apply/inventory/trust/readiness and deploy chain through
  exact terminal Scylla-install authorization/execution/evidence, current
  source/catalog, and the unchanged `IN_PROGRESS/VERIFY` journal. Caller
  results, statuses, steps, targets, paths, runners, executables, and
  toolchains are forbidden.
  Require complete unique evidence for every authorized Scylla stable ID:
  exact terminal success, consumed execution authorization, catalog-bound
  2026.2 package/repository/signing-key provenance, installed or no-change
  state, masked/inactive `scylla-server`, and no configuration, storage,
  tuning, Manager, or service-start action. Prepared, started, failed,
  uncertain, manual-recovery, missing, extra, duplicate, malformed, stale, or
  provenance-drifted state fails before persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-scylla-install-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-scylla-install-reconciliation.json`.
  Mark only exact mapping-position-eleven `scylla-install` instances
  evidence-bound `succeeded`. Advance only fully proven immediate
  mapping-position-twelve `scylla-configure` scopes to
  `evidence-ready-authorization-required`; never leapfrog to bootstrap,
  Manager/monitoring agents, health, or later gates. Build fully in memory
  before atomic owner-only no-follow persistence. Exact reuse is zero-write and
  conflicts fail closed. Reports retain only schemas, digests, bounded
  install/change/service/step/next-gate counts, blocker enums, and unchanged
  journal state. This owner must not authorize or execute, invoke a process,
  mutate prior artifacts or the journal, finalize, or add CLI/public deploy
  wiring.
- The internal deploy `scylla-configure` authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and one already-normalized ordinary approval
  proof. It must canonically reload and revalidate the complete verified
  Terraform/apply/inventory/trust/readiness and deploy chain through exact
  post-`scylla-install` reconciliation before persistence.
  Derive only active mapping-position-twelve `scylla-configure` instances
  whose exact status is `evidence-ready-authorization-required`, their
  canonical Scylla stable-ID targets, and the complete value-free
  configuration intent from current desired state, observation, inventory,
  package evidence, catalog, and packaged source. Bind cluster/datacenter/rack
  and private identities, deterministic initial-stable-ID seed policy, exact
  ScyllaDB 2026.2 package version, fixed data directories, wrapper-owned
  templates and rendered files, role/playbook source, variables, command, and
  masked/inactive service policy through bounded counts, enums, and digests.
  Caller targets, topology, identities, seeds, versions, directories,
  configuration values, variables, commands, paths, scopes, prompts, and
  free-form text are forbidden. Require ordinary interactive approval or
  PLAN-permitted `cli-yes`; reject destructive flags and scope proof as
  inapplicable. Approval never bypasses topology, RFC 1918 address, seed,
  install, storage, service, readiness, source, provenance, or drift gates.
  Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-configure-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-configure-authorization.json`.
  Persist only schemas, digests, bounded counts, enums, and booleans; omit
  addresses, configuration text, seed identities, provider IDs, commands,
  variable values, paths, credentials, and secrets. Exact reuse is zero-write;
  changed proof, intent, scope, or provenance requires a new operation.
  Authorization remains unconsumed, execution unavailable, and the common
  journal and all prior artifacts byte-for-byte unchanged. This owner must
  not invoke a runner/toolchain, create execution intent or evidence, mutate
  configuration or service state, advance a later gate, finalize, or add
  CLI/public deploy wiring.
- The internal deploy `scylla-configure` execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically reload and revalidate the complete verified Terraform/apply/
  inventory/trust/readiness and deploy chain through exact post-install
  reconciliation, immutable unconsumed configure authorization, current
  source/catalog, and unchanged `IN_PROGRESS/VERIFY` journal before every
  effect.
  Derive only exact authorized mapping-position-twelve `scylla-configure`
  scopes, one stable ID per call, typed protected configuration values, and
  anchored source/variable/command/configuration intent from immutable
  canonical records. Caller steps, targets, limits, configuration, variables,
  paths, commands, environments, authorization, results, and loop controls are
  forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-configure-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-scylla-configure-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-configure-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-configure-evidence.json`.
  Record retry-safe `prepared`, then durable `started` immediately before each
  controlled call; the first started attempt consumes the whole immutable
  authorization without rewriting it. Require strict complete exact target,
  source, variable, command, 2026.2, cluster/datacenter/rack/seed/data-directory/
  template/configuration and exact two-file identity, root ownership, `0644`
  modes, masked/inactive service, and runtime-validation-not-performed evidence.
  Package installation, storage mutation, tuning, firewall, SSH, Manager,
  service start, bootstrap, or any other configuration file is forbidden.
  Exit zero alone is insufficient.
  Once started, crash, timeout, interruption, failed/unreachable/nonzero,
  malformed/non-UTF-8/oversized output, semantic mismatch, post-call drift, or
  persistence failure is manual-recovery-required and permanently forbids
  retry, replay, skip, continuation, or rollback. An exact prepared prefix may
  resume before invocation, an exact succeeded prefix may continue only in
  immutable order, and complete re-entry is zero-process. Evidence and reports
  retain only stable IDs, bounded states/booleans/counts, schemas, and digests;
  omit addresses, seeds, configuration text, provider IDs, commands, variable
  values, environment, paths, output, credentials, and secrets. Keep the
  authorization, prior artifacts, step reconciliations, and common journal
  byte-for-byte unchanged at VERIFY. This owner must not reconcile the result,
  bootstrap Scylla, authorize or execute another stage, finalize, or add
  CLI/public deploy wiring.
- The internal post-`scylla-configure` reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must canonically reload and revalidate the full
  chain through exact terminal configure authorization/execution/evidence.
  Require complete unique success for every authorized Scylla stable ID, exact
  2026.2 and two-file root-owned `0644` configuration identity, current
  cluster/datacenter/rack/private-identity/seed/data-directory/template/source/
  variable/command digests, masked/inactive service, and explicit absence of
  runtime validation, package/storage/tuning/firewall/SSH/Manager/start/
  bootstrap behavior. Prepared, started, failed, uncertain, incomplete,
  duplicate, stale, or drifted state fails before persistence.
  Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-scylla-configure-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-scylla-configure-reconciliation.json`.
  Mark only exact mapping-position-twelve `scylla-configure` instances
  evidence-bound `succeeded`. Preserve the original immutable 21-position
  deploy mapping byte-for-byte: it historically omits `scylla-bootstrap`, so
  never rewrite/reorder it or infer that mapped `scylla-health` is now
  eligible. Until a separately versioned bootstrap context/plan exists,
  persist the stable `bootstrap-plan-required` and
  `bootstrap-step-unmodeled` blockers, keep bootstrap/empty-cluster/topology/
  seed/health/capacity evidence `not-performed`, and expose no next mutation
  authorization or execution. Exact reuse is zero-write and reports retain
  only bounded counts, enums, blocker names, and digests. Keep the common
  journal and all prior artifacts unchanged at `IN_PROGRESS/VERIFY`. This
  owner must not invoke a runner/toolchain, create authorization/execution
  intent, bootstrap or health-check Scylla, finalize, or add CLI/public wiring.
- The internal deploy Scylla bootstrap context/plan owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and an optional normalized reviewed new-cluster
  proof. It must canonically reload the full chain through exact
  post-`scylla-configure` reconciliation, including initial Terraform
  state/apply, observation/inventory/trust/readiness, storage/install/config,
  source/catalog, and unchanged `IN_PROGRESS/VERIFY` journal evidence.
  Persist separate immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-context/v1` then
  `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-plan/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-context.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-plan.json`.
  Never modify the historical 21-position deploy plan.
  Prove or block a new empty cluster from exact deploy intent, absent prior
  Terraform state or an exact create-only/drift-free initial observation, no
  prior bootstrap/membership artifacts, every Scylla service masked/inactive
  and never started, exact current stable set/config/topology/seeds, and
  reviewed capacity sufficiency. Unknown remains a blocker. Derive order only
  from the configured initial stable-ID seed, topology, and stable identity. The first
  target is `initial-seed`; every remaining target is `join-existing`, serial
  one, and must wait for its preceding bootstrap plus complete current
  cluster-health, healthy-survivor, target-absence, capacity, and schema
  checkpoints. Expected Host IDs remain unknown before start.
  A complete initial-seed proof may produce only
  `authorization-required`; this owner must not create authorization or
  execution records, invoke a runner, change the journal, or wire public/CLI
  behavior. Persist only bounded enums/counts and redacted digests without
  addresses, seed identities, configuration values, provider IDs, or Host
  IDs. Build both records in memory, persist context before plan, recover an
  exact context-only prefix, reuse exact records without writes, and fail every
  changed proof, provenance, path, or ambiguous artifact closed.
- The internal deploy Scylla initial-seed authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and one normalized approval proof. It must
  canonically reload and reproduce the full chain plus exact immutable
  bootstrap context/plan before persistence. Derive only sequence-one
  `initial-seed` and bind its exact target/mode/order/topology/seed/version/
  storage/configuration/capacity/source/empty-cluster digests. Caller targets,
  modes, order, seeds, commands, variables, paths, and values are forbidden.
  Treat the registry class as sensitive: require ordinary interactive or
  PLAN-permitted `cli-yes` approval plus a separate exact digest-only narrow
  scope acknowledgement. `cli-yes` never supplies the narrow proof.
  Destructive flags and scope proof are inapplicable and must be refused.
  Never bypass empty-cluster, identity, storage, configuration, masked/
  inactive and never-started service, topology, seed, capacity, trust,
  readiness, source, journal, or drift gates.
  Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-authorization.json`.
  Keep every `join-existing` step excluded and waiting for a later complete
  health checkpoint. Exact reuse is zero-write; changed proof, scope, or
  provenance requires a new operation. Authorization remains unconsumed,
  execution unavailable, and the common journal and prior artifacts unchanged
  at `IN_PROGRESS/VERIFY`. Persist/report only bounded enums, counts, and
  redacted digests without addresses, seed/configuration values, Host IDs,
  provider IDs, commands, variables, paths, free text, credentials, or
  secrets. This owner must not invoke a runner/toolchain, start Scylla, create
  execution/evidence records, finalize, or add CLI/public wiring.
- The internal deploy Scylla initial-seed execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically revalidate the full chain through the immutable bootstrap context,
  plan, and unconsumed authorization before every effect. Derive only the exact
  sequence-one `initial-seed` target, mode, topology, configured sole seed,
  configuration-file identities, storage/package version, variables, source,
  and anchored command from canonical state. Caller targets, modes, scopes,
  seeds, topology, versions, variables, commands, paths, results, and retry
  controls are forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-execution/v1` and immutable
  owner-only `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-evidence/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-evidence.json`.
  Record retry-safe `prepared`, then durable `started` immediately before the
  sole controlled call; `started` consumes both ordinary and narrow
  authorization without rewriting the immutable authorization.
  Invoke only hash-checked `scylla-bootstrap`, exact one target, serial one,
  check mode refused. Require strict exact target/mode/prerequisite identity,
  pre-start revalidation, unmask/start boundary, bounded CQL readiness and
  argv-form nodetool membership/schema/streaming evidence; exit zero alone is
  insufficient. Persist only stable ID, hashed Host/ring identities, bounded
  topology/version/status booleans, and digests without addresses, raw Host IDs,
  output, configuration, seeds, commands, variables, paths, credentials, or
  secrets.
  A strict successful result completes only initial-seed execution. A strict
  failed result remains manual-recovery/no-retry: preserve a possibly joined
  node, and accept remask evidence only when the source contract proves the
  target never joined. Any crash, timeout, interruption, unreachable/nonzero or
  malformed result, drift, or post-call persistence failure after `started` is
  permanently uncertain and forbids retry, restart, destroy, or removenode.
  Exact successful re-entry is zero-process. Keep every join unauthorized,
  health reconciliation not-performed, the common journal and prior artifacts
  byte-for-byte unchanged at `IN_PROGRESS/VERIFY`, and public/CLI wiring absent.
- The internal deploy first-join authorization owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, and one already-normalized approval proof. It must canonically
  reload and reproduce the immutable bootstrap plan, exact successful
  initial-seed execution/evidence, complete current health execution/evidence/
  checkpoint, first-join safety context/evidence/reconciliation, and their full
  current Terraform/observation/inventory/trust/readiness/storage/install/
  configuration/source/catalog/journal chain before persistence.
  Derive only exact sequence two when it remains the first reconciled
  `authorization-required` `join-existing` target. Bind the exact target/mode,
  bootstrap/health/safety step identities, current survivor and active-seed
  set, topology/schema/membership, target topology, package version, storage,
  configuration, capacity, seed policy, source, and every required safety gate
  through counts/enums/digests. Caller target, mode, scope, survivor, seed,
  topology, configuration, version, storage, command, variables, paths, and
  free-form input are forbidden. Every later join remains waiting and excluded.
  Require ordinary interactive or PLAN-permitted `cli-yes` approval plus a
  separate exact digest-only target/mode/scope acknowledgement; `cli-yes` alone
  is insufficient. Destructive flags and scope proof are inapplicable. Never
  bypass target absence, capacity, survivor/seed health, schema, streaming,
  completed-prior-membership, topology, storage, trust, readiness, source,
  journal, or drift gates.
  Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-join-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-join-authorization.json`.
  Exact reuse is zero-write; changed proof, scope, gate, or provenance requires
  a new operation. Authorization remains unconsumed, execution unavailable,
  and the common journal and every prior artifact unchanged at
  `IN_PROGRESS/VERIFY`. Persist/report only bounded enums, counts, and redacted
  digests without addresses, raw Host IDs, seed identities, provider IDs,
  configuration values, commands, variables, paths, prompts/free text,
  credentials, or secrets. This owner must not invoke a runner/toolchain,
  start Scylla, create execution/evidence records, finalize, or add CLI/public
  wiring.
- The internal deploy first-join execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically reload and reproduce the immutable bootstrap plan/context, exact
  successful initial-seed execution/evidence, complete current health
  execution/evidence/checkpoint, first-join safety context/evidence/
  reconciliation, unconsumed first-join authorization, source, catalog, and
  unchanged `IN_PROGRESS/VERIFY` journal before every effect.
  Derive only exact authorized sequence-two `join-existing`, including its
  target, mode, order, topology, configuration, storage, package version,
  active seeds, healthy survivors, capacity, source, variables, and anchored
  command. Caller scope, target, mode, seeds, survivors, variables, commands,
  paths, results, and retry controls are forbidden.
  Persist independently versioned owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-join-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-scylla-join-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-join-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-join-evidence.json`.
  Record retry-safe `prepared`, then durable `started` immediately before the
  sole controlled call; `started` consumes both ordinary and narrow
  authorization without rewriting the immutable authorization.
  Invoke only hash-checked `scylla-bootstrap`, exact one target, serial one,
  check mode refused. Require strict exact target/mode/prerequisite/pre-start/
  source/command/variable intent plus CQL readiness, membership/topology,
  schema agreement, and completed streaming semantics; exit zero alone is
  insufficient.
  Any crash, timeout, interruption, nonzero/unreachable/malformed result,
  post-start drift, or post-effect persistence failure is permanently
  manual-recovery/no-retry. Exact successful re-entry is zero-process. Keep
  every later join waiting and the common journal and prior records
  byte-for-byte unchanged at `IN_PROGRESS/VERIFY`. Persist and report only
  bounded enums/booleans/counts, stable ID, and redacted digests without
  addresses, raw Host IDs, provider IDs, seed/configuration values, output,
  commands, variables, environment, protected paths, credentials, or secrets.
  This owner must not reconcile later health, authorize another join, finalize,
  or add CLI/public wiring.
- The internal post-first-join health owner accepts only canonical state-root/
  cluster identity, one operation UUID, the matching already-held deploy lock,
  a controlled runner, and an exact validated sibling Ansible executable pair
  with its explicit supported toolchain dependency. It must canonically reload
  and reproduce the immutable bootstrap context/plan, exact initial-seed and
  sequence-two authorization/execution/evidence, pre-join health checkpoint,
  join-safety chain, source, catalog, and unchanged `IN_PROGRESS/VERIFY`
  journal before every effect.
  This boundary owns a fresh exact complete-current-set `scylla-health` call:
  pre-join health covers only the initial-seed prefix, and bootstrap result
  evidence is never cluster-health evidence. Reuse the existing controlled
  service, strict payload builder, hash-checked source, and parser rather than
  adding command or parser logic. Derive only the initial seed and exact
  sequence-two joined target; caller targets, limits, variables, commands,
  paths, results, and retry controls are forbidden.
  Persist independently versioned owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-join-health-execution/v1`,
  `deploy-scylla-vms.ansible-deploy-scylla-join-health-evidence/v1`, and
  `deploy-scylla-vms.ansible-deploy-scylla-join-health-reconciliation/v1`
  only under `<cluster-root>/operations/`. Record durable `started` before the
  sole process call. Require exact hashed Host-ID membership, all members Up
  Normal, cross-view identity/topology/schema agreement, idle streaming,
  service/API/CQL readiness, and current storage/configuration/source
  provenance; exit zero and bootstrap success are insufficient.
  Any crash, timeout, interruption, malformed or semantically incomplete
  result, post-call drift, or post-effect persistence uncertainty is
  permanently manual-recovery/no-retry. An exact succeeded execution/evidence
  prefix may recover only missing reconciliation without a process; exact
  complete re-entry is zero-process/zero-write. Reconciliation marks only
  sequences one and two health-succeeded and derives at most sequence three.
  Preserve generic replication/backup `not-performed` and quorum/capacity
  `unknown` truth, so the next join remains blocked until a distinct
  operation-specific safety owner resolves its reviewed gates; every later
  join remains waiting.
  Keep addresses, raw Host IDs, provider IDs, seed/configuration values,
  routes, commands, variables, environment, raw output, protected paths,
  credentials, and secrets out of records and reports. Keep all prior
  artifacts and the common journal byte-for-byte unchanged at VERIFY. This
  owner must not create authorization, execute another bootstrap, finalize, or
  add CLI/public wiring.
- The internal sequence-three `join-existing` safety owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and normalized typed external safety proofs from
  the existing join-safety contract. It must canonically reload and revalidate
  terminal-success sequence-two execution/evidence and consumed authorization,
  the fresh post-first-join health execution/evidence/reconciliation, immutable
  bootstrap context/plan, current Terraform/observation/inventory/trust/
  readiness/storage/install/configuration/source/catalog provenance, and the
  unchanged `IN_PROGRESS/VERIFY` journal.
  Derive only exact contiguous sequence three in `join-existing` mode: sequences
  one and two must remain completed and healthy, the target must be absent from
  exact current healthy membership, and every later sequence remains waiting.
  Bind exact survivors and active seeds, cross-view membership/topology/schema/
  streaming, target topology/configuration/storage/package, route/trust/
  readiness, no-competing-operation, and independent capacity, replication,
  quorum, and backup-policy gates. Unknown is always a blocker; never infer
  target absence or policy safety from process success.
  Persist independently versioned immutable owner-only context, evidence, and
  reconciliation records only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-sequence-three-join-safety-{context,evidence,reconciliation}.json`.
  Build all records in memory, publish context first, recover only exact
  prefixes, reuse exact records without writes, and fail every conflict closed
  without overwrite, deletion, rollback, or adaptation. Reconciliation may
  mark only exact sequence three `authorization-required` when every required
  gate is current and passed; otherwise it remains blocked, and no later
  sequence advances. Keep reports and records limited to bounded enums/counts,
  policy-permitted stable IDs, and redacted digests. This owner must not create
  authorization/execution, invoke a process, transition the journal, finalize,
  or add CLI/public wiring.
- The internal sequence-three `join-existing` authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and one already-normalized approval proof. It must
  canonically reload and reproduce the full chain through successful
  sequence-two execution with consumed proofs, fresh post-first-join complete-
  set health, and exact sequence-three safety context/evidence/reconciliation.
  Derive only exact sequence three when its safety reconciliation is
  `authorization-required`; sequences one and two remain health-succeeded and
  every later join remains waiting and excluded.
  Bind target/mode/order/topology/seed/survivor/membership/schema/streaming/
  package/storage/configuration/capacity/replication/quorum/backup/source and
  safety identities through bounded values and digests. Require ordinary
  interactive or PLAN-permitted `cli-yes` approval plus a separate exact
  digest-only target/mode/scope acknowledgement; `cli-yes` alone is
  insufficient. Destructive flags and scope proof are inapplicable. Every
  target-absence, health, topology, provenance, trust, readiness, source,
  journal, and drift gate remains mandatory.
  Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-authorization/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-sequence-three-join-authorization.json`.
  Exact reuse is zero-write and every changed proof, scope, gate, or provenance
  fails closed and requires a new operation. Authorization remains unconsumed,
  execution unavailable, and the common journal and prior records unchanged at
  `IN_PROGRESS/VERIFY`. Keep records/reports limited to bounded enums, counts,
  and redacted digests. This owner must not invoke a runner/toolchain, start
  Scylla, create execution/evidence records, finalize, or add CLI/public wiring.
- The internal sequence-three `join-existing` execution owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, a controlled runner, and an exact validated sibling
  Ansible executable pair with its explicit supported toolchain dependency. It
  must canonically reload and reproduce the immutable bootstrap context/plan,
  successful initial-seed and sequence-two authorization/execution/evidence,
  fresh post-first-join health, sequence-three safety context/evidence/
  reconciliation, unconsumed sequence-three authorization, current
  infrastructure/Ansible provenance, source, catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal before every effect.
  Derive only exact authorized sequence-three `join-existing`, including its
  target, mode, order, topology, configuration, storage, package version,
  active seeds, healthy survivors, capacity and policy evidence, source,
  variables, and anchored command. Caller scope, target, mode, order, variables,
  commands, paths, results, and retry controls are forbidden. Every later join
  remains waiting and excluded.
  Persist independently versioned owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-execution/v1`
  and
  `deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-evidence/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-sequence-three-join-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-sequence-three-join-evidence.json`.
  Record retry-safe `prepared`, then durable `started` immediately before the
  sole controlled call; `started` consumes both ordinary and narrow
  authorization without rewriting the immutable authorization.
  Invoke only hash-checked `scylla-bootstrap`, exact one target, serial one,
  check mode refused. Require strict exact target/mode/prerequisite/pre-start/
  source/command/variable intent plus CQL readiness, membership/topology,
  schema agreement, and completed streaming semantics; exit zero alone is
  insufficient. Persist semantic evidence before terminal success.
  Any crash, timeout, interruption, nonzero/unreachable/malformed result,
  post-start drift, or post-effect persistence failure is permanently
  manual-recovery/no-retry. Exact prepared recovery is allowed only before
  invocation; exact successful re-entry is zero-process/zero-write. Keep post-
  sequence-three health not-performed, every later join waiting, and the common
  journal and prior records byte-for-byte unchanged at `IN_PROGRESS/VERIFY`.
  Persist and report only bounded enums/booleans/counts, the permitted target
  stable ID, and redacted digests without addresses, raw Host IDs, provider
  IDs, seed/configuration values, routes, output, commands, variables,
  environment, protected paths, credentials, or secrets. This owner must not
  run post-join health, authorize another join, finalize, or add CLI/public
  wiring.
- The internal post-sequence-three join health owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically reload the complete current infrastructure, storage, install,
  configuration, bootstrap, post-first-join health, sequence-three safety,
  authorization, terminal-success execution/evidence, source/catalog, and
  unchanged `IN_PROGRESS/VERIFY` journal chain before every effect.
  Run only the existing hash-checked read-only `scylla-health` source over the
  exact complete current set through sequence three. Persist independently
  versioned owner-only execution, evidence, and reconciliation companions only
  at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-post-sequence-three-join-health-{execution,evidence,reconciliation}.json`.
  Record durable `started` before the sole process call and require exact unique
  hashed membership, all members Up Normal, cross-view topology/schema
  agreement, idle streaming, service/API/CQL readiness, and current storage/
  configuration/source provenance. Exit zero and bootstrap success are
  insufficient. Replication and backup remain `not-performed`; quorum and
  capacity remain `unknown`.
  Any post-start crash, timeout, interruption, nonzero/unreachable/malformed
  result, drift, or persistence uncertainty is permanent manual-recovery/no-
  retry. Exact completed re-entry is zero-process/zero-write; an exact
  execution/evidence prefix may recover reconciliation only. Reconciliation
  clears only sequence-three health. When another bootstrap step exists, leave
  it waiting for a separately versioned safety context; otherwise report
  bootstrap-sequence-complete and next-step-not-required. Never create later
  safety, authorization, or execution, leapfrog a gate, mutate prior records or
  the journal, finalize deploy, or add CLI/public wiring. Persist and report
  only bounded states, counts, stable IDs, and redacted digests without
  addresses, raw Host IDs, provider IDs, routes, seed/configuration values,
  commands, variables, environment, raw output, protected paths, credentials,
  or secrets.
- The internal generic later-join safety owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, and normalized typed external safety proofs from the established
  join-safety contract. It must canonically reload and revalidate the complete
  chain through the immutable bootstrap context/plan, exact contiguous
  successful completed prefix through sequence three or later, consumed prior
  authorizations/executions/evidence, latest fresh complete-current-set health,
  current infrastructure/Ansible provenance, source/catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal.
  Derive the first unfinished bootstrap-plan sequence exclusively from that
  canonical state. The caller may never select a sequence, target, order, mode,
  address, command, variable, path, or free-form value. If no step remains,
  return strict `not-required`, accept no proofs, and write nothing. Otherwise
  the step must be exact `join-existing` at sequence `>=4`; every later step
  remains waiting and excluded.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-later-join-safety-{context,evidence,reconciliation}/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-later-join-sequence-<sequence>-safety-{context,evidence,reconciliation}.json`.
  Each canonically derived sequence has one immutable path family so completed
  sequence history coexists without ambiguity. Build all records in memory,
  publish context then evidence then
  reconciliation, recover only exact prefixes, and reuse exact records without
  writes. A changed sequence, proof, completed prefix, health checkpoint, or
  provenance conflicts and fails closed without overwrite, deletion, rollback,
  or adaptation.
  Bind exact completed-prefix and current healthy membership, survivor and
  active-seed sets, cross-view topology/schema/streaming, target absence/
  topology/configuration/storage/package, route/trust/readiness, capacity/
  replication/quorum/backup policy, no-competing-operation, source/catalog,
  and journal truth through bounded values and digests. Unknown is always a
  blocker. Reconciliation may mark only the derived immediate sequence
  `authorization-required`; it must not authorize, execute, invoke health,
  advance another join, transition the journal, finalize, or add public/CLI
  wiring. Keep records and reports limited to bounded enums/counts, the derived
  sequence, policy-permitted stable IDs, and redacted digests.
- The internal generic later-join authorization owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, and one optional already-normalized approval proof. It must
  canonically reload and reproduce the complete current infrastructure,
  storage/install/configuration, bootstrap, contiguous completed-join prefix,
  latest fresh complete-set health, generic later-join safety context/evidence/
  reconciliation, source/catalog, and unchanged `IN_PROGRESS/VERIFY` journal
  chain before persistence.
  Derive only the exact first unfinished reconciliation target. If no planned
  join remains, accept no proof, create no authorization, and return strict
  `not-required`. Otherwise the target must be the exact
  `authorization-required` `join-existing` sequence `>=4`; every later step
  remains waiting and excluded. Caller target, sequence, order, mode, scope,
  survivor, seed, topology, configuration, storage, version, command,
  variable, path, prompt, and free-form values are forbidden.
  Bind the exact completed prefix, target/mode/order, topology, active seed and
  survivor sets, membership/schema/streaming, package/storage/configuration/
  capacity, replication/quorum/backup, source, and safety identities through
  bounded counts, enums, and digests. Require ordinary interactive or
  PLAN-permitted `cli-yes` approval plus a separate exact digest-only
  target/mode/sequence/scope acknowledgement; `cli-yes` alone is insufficient.
  Destructive flags and scope proof are inapplicable and must be refused.
  Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-later-join-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-later-join-sequence-<sequence>-authorization.json`.
  Exact reuse is zero-write; every changed sequence, proof, scope, gate,
  completed prefix, health checkpoint, or provenance fails closed and requires
  a new operation without overwrite, deletion, rollback, or adaptation.
  Authorization remains unconsumed, execution unavailable, and the common
  journal and prior records unchanged. Persist and report only bounded enums,
  counts, and redacted digests without addresses, raw Host IDs, provider IDs,
  routes, seed/configuration values, commands, variables, environment, paths,
  prompts/free text, credentials, or secrets. This owner must not invoke a
  runner/toolchain, start Scylla, create execution/evidence/health records,
  finalize, or add CLI/public wiring.
- The internal generic later-join execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  canonically reload and reproduce the complete current infrastructure,
  storage/install/configuration, bootstrap, contiguous completed-join prefix,
  latest fresh complete-set health, generic later-join safety context/evidence/
  reconciliation, unconsumed generic authorization, source/catalog, and
  unchanged `IN_PROGRESS/VERIFY` journal before every effect.
  Derive only the authorization's exact first unfinished `join-existing`
  sequence `>=4`, including its completed prefix, target/mode/order, topology,
  storage, configuration, package, active seeds, healthy survivors, capacity,
  source, variables, and anchored command. Caller sequence, target, mode,
  order, scope, variables, commands, paths, results, and retry controls are
  forbidden; every later step remains waiting and excluded.
  Persist independently versioned owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-later-join-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-scylla-later-join-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-later-join-sequence-<sequence>-{execution,evidence}.json`.
  Record retry-safe `prepared` after full validation, then durable `started`
  immediately before the sole controlled call; `started` consumes both
  ordinary and narrow authorization without rewriting the immutable
  authorization. Invoke only hash-checked `scylla-bootstrap`, exact one target,
  serial one, with check mode refused. Require strict target/sequence/mode/
  prerequisite/pre-start/source/command/provenance parity plus bounded
  membership/schema/streaming semantics; exit zero alone is insufficient.
  Persist semantic evidence before terminal success.
  Any crash, timeout, interruption, unreachable/nonzero/malformed result,
  post-start drift, or persistence uncertainty is permanently manual-recovery/
  no-retry. Prepared recovery is allowed only before invocation; exact complete
  re-entry is zero-process/zero-write. A changed sequence, proof, prefix, or
  provenance and every conflicting artifact fail closed without overwrite,
  deletion, rollback, or adaptation. Keep the next join waiting for separate
  fresh complete-set health and safety, and keep prior records plus the common
  journal unchanged at `IN_PROGRESS/VERIFY`. Persist/report only bounded
  enums, booleans, counts, stable IDs, and redacted digests without addresses,
  raw Host IDs, provider IDs, routes, seed/configuration values, commands,
  variable values, environment, raw output, protected paths, credentials, or
  secrets. This owner must not run post-join health, authorize another join,
  finalize, or add CLI/public wiring.
- The internal generic post-later-join health owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its explicit supported toolchain dependency. It must
  reload the full chain through the exact successful generic later join and
  derive that completed sequence exclusively from canonical records.
  Run only the existing hash-checked read-only `scylla-health` source over the
  exact complete current stable-ID set. Persist independently versioned
  owner-only execution, evidence, and reconciliation records per sequence only
  at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-post-later-join-sequence-<sequence>-health-{execution,evidence,reconciliation}.json`.
  Record durable `started` before the sole process call and require complete
  unique Up Normal membership, cross-view identity/topology/schema agreement,
  idle streaming, service/API/CQL readiness, and current storage/configuration
  provenance; exit zero alone is insufficient. Replication and backup remain
  `not-performed`; quorum and capacity remain `unknown`.
  Any post-start crash, timeout, interruption, nonzero/unreachable/malformed
  result, drift, or persistence uncertainty is permanent manual-recovery/
  no-retry. Exact complete re-entry is zero-process/zero-write. Reconciliation
  may report bootstrap completion or expose only the next derived sequence for
  its separate sequence-keyed safety stage; it must not collect safety proofs,
  authorize or execute the next join, mutate prior records or the journal,
  finalize, or add CLI/public wiring. Keep addresses, raw Host IDs, provider
  IDs, routes, seed/configuration values, commands, variables, environment,
  output, protected paths, credentials, and secrets absent.
- The internal post-bootstrap deploy-mapping bridge accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching already-
  held deploy lock. It must canonically reload the exact full chain through
  the immutable bootstrap plan, every contiguous terminal-success bootstrap
  execution with consumed authorization and semantic evidence, and the final
  fresh complete-current-set health execution/evidence/reconciliation. Select
  the initial-seed, first-join, sequence-three, or sequence-keyed later-join
  health family solely from the plan's final sequence; missing, extra,
  partial, prepared, started, failed, uncertain, stale, or drifted artifacts
  fail closed.
  Persist only immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-post-bootstrap-reconciliation/v1`
  at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-post-bootstrap-reconciliation.json`.
  Recompute and preserve the historical 21-position mapping without rewriting
  any context, plan, or prior reconciliation. Resolve only its explicit
  bootstrap boundary, bind the final strict health evidence to mapped
  `scylla-health`, and advance only immediate `manager-server` to
  `evidence-ready-authorization-required`; all later mapped work remains
  blocked/not-performed. Replication and backup remain `not-performed`, while
  quorum and capacity remain `unknown`. Exact reuse is zero-write, the journal
  remains `IN_PROGRESS/VERIFY`, and the owner must not authorize, execute,
  invoke a process, finalize, or add CLI/public wiring.
- The internal deploy `manager-server` authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and one normalized ordinary approval proof. It
  must canonically reload the full verified infrastructure/deploy chain
  through the exact post-bootstrap bridge plus current source, catalog,
  inventory, trust, readiness, base-OS, and unchanged
  `IN_PROGRESS/VERIFY` journal evidence.
  Derive only the exact active mapping-position-fourteen `manager-server`
  instance whose status is `evidence-ready-authorization-required`, the
  canonical manager stable ID, mutating classification, Ubuntu 24.04
  architecture, exact Manager 3.12 package/repository/signing-key provenance,
  and masked/inactive/unconfigured policy. Missing, extra, wrong-role,
  wrong-step, stale, drifted, or unready scope fails closed.
  Require ordinary interactive or PLAN-permitted `cli-yes`; destructive and
  narrow proofs are inapplicable and approval never bypasses a prerequisite
  or ordering gate. Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-manager-server-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-manager-server-authorization.json`.
  Exact reuse is zero-write; changed proof, scope, or provenance requires a
  new operation. Authorization remains unconsumed and execution unavailable.
  Records and reports retain only bounded schemas, digests, counts, enums,
  booleans, and the permitted stable ID. This owner must not invoke a runner,
  install packages, configure a backend, start Manager, create execution
  records, change the journal, advance later work, or add CLI/public wiring.
- The internal deploy `manager-server` execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its supported toolchain dependency. It must canonically
  reload the full verified infrastructure/deploy/bootstrap/final-health/
  post-bootstrap bridge chain, immutable unconsumed authorization, current
  source/catalog/controller files, and unchanged `IN_PROGRESS/VERIFY` journal
  before every effect.
  Derive only the exact authorized mapping-position-fourteen manager stable ID,
  Ubuntu 24.04 architecture, Manager 3.12 package/repository/authenticated-key
  provenance, install-only variables/source, and anchored command. Caller
  targets, packages, versions, repositories, keys, variables, commands, paths,
  results, and retry controls are forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-manager-server-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-manager-server-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-manager-server-{execution,evidence}.json`.
  Record retry-safe `prepared`, then durable `started` immediately before the
  sole controlled call; `started` consumes the whole immutable authorization
  without rewriting it. Invoke only the hash-checked `manager-server` source,
  exact one target, serial one, with check mode disabled. Require exact
  target/package/repository/key/source/command/provenance parity,
  installed-or-no-change success, masked/inactive `scylla-manager`, and absent
  backend/configuration/setup/registration/task/service-start actions. Exit
  zero alone is insufficient and evidence must precede terminal success.
  Once started, crash, timeout, interruption, unreachable/nonzero or malformed
  execution, semantic mismatch, drift, or persistence uncertainty is
  manual-recovery/no-retry and forbids replay, skip, continuation, or rollback.
  Exact prepared recovery is allowed only before invocation; exact complete
  re-entry is zero-process/zero-write. Keep the authorization, bridge, prior
  plans, and common journal unchanged at VERIFY. Records and reports retain
  only bounded schemas, digests, counts, enums, booleans, and the permitted
  stable ID; omit addresses, provider IDs, routes, repository URLs, key
  material, configuration/backend values, commands, variables, environments,
  output, protected paths, credentials, and secrets. This owner must not
  reconcile or authorize later work, configure/register/start Manager, run
  Manager tasks, finalize, or add CLI/public wiring.
- The internal post-`manager-server` result reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must canonically reload and revalidate the full
  verified infrastructure/deploy/bootstrap/final-health/post-bootstrap chain,
  exact Manager authorization/execution/evidence, source/catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal. Require terminal-success execution, consumed
  execution authorization, one complete unique Manager 3.12 installed-or-no-
  change result for the canonical manager target, exact package/repository/key/
  source/command provenance, masked/inactive `scylla-manager`, and absent
  backend/configuration/setup/registration/task/service-start actions. Every
  prepared, started, failed, uncertain, recovery-required, missing, duplicate,
  stale, conflicting, or drifted state fails before persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-manager-server-reconciliation/v1` only
  at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-manager-server-reconciliation.json`.
  Recompute and preserve the historical 21-position mapping, mark only exact
  mapped `manager-server` evidence-bound succeeded, and evaluate only the
  immediate next active gate from current canonical evidence. Read-only work
  may become `eligible`; mutating work may become only
  `evidence-ready-authorization-required`; blocked gates retain their exact
  blockers and no later gate leapfrogs. Exact reuse is zero-write and conflicts
  fail closed without overwrite, deletion, rollback, or adaptation. Keep the
  journal and all prior records byte-for-byte unchanged. Records and reports
  retain only bounded schemas, digests, counts, enums, and booleans without
  addresses, provider IDs, routes, repository URLs, key material,
  configuration/backend values, commands, variables, environments, output,
  protected paths, credentials, or secrets. This owner must not create
  authorization/execution intent, invoke a runner/toolchain, configure a
  backend, register/start Manager, infer Manager health, finalize, or add
  CLI/public wiring.
- The internal deploy `monitoring-stack` authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and one normalized ordinary approval proof. It
  must canonically reload the full verified infrastructure/deploy/bootstrap/
  final-health/Manager chain through exact post-`manager-server`
  reconciliation plus current source, catalog, monitoring-role inventory,
  trust, readiness, base-OS, and unchanged `IN_PROGRESS/VERIFY` journal
  evidence.
  Derive only the exact active mapping-position-fifteen `monitoring-stack`
  instance whose status is `evidence-ready-authorization-required`, the exact
  single monitoring stable ID, mutating classification, Ubuntu 24.04
  architecture, digest-pinned official Scylla Monitoring 4.16.0 archive and
  exact component/source provenance, and archive-install-only policy. Docker
  installation/image pulls, Compose/auth/target generation, containers,
  service start, public binds, Manager registration, Scylla start, and secrets
  are forbidden.
  Require ordinary interactive or PLAN-permitted `cli-yes`; destructive and
  narrow proofs are inapplicable and approval never bypasses role, OS,
  base-OS, trust, readiness, source, archive, provenance, no-public-bind,
  ordering, or drift gates. Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-monitoring-stack-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-monitoring-stack-authorization.json`.
  Exact reuse is zero-write; changed proof, scope, or provenance requires a
  new operation. Authorization remains unconsumed and execution unavailable;
  all prior artifacts and the journal remain unchanged. Records and reports
  retain only bounded schemas, digests, counts, enums, booleans, and the
  permitted stable ID, omitting addresses, provider IDs, routes, archive URLs,
  file paths, auth/configuration values, commands, variables, environments,
  prompts/free text, credentials, and secrets. This owner must not invoke a
  runner/toolchain, install the archive, create execution records, advance a
  later gate, change the journal, finalize, or add CLI/public wiring.
- The internal deploy `monitoring-stack` execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its supported toolchain dependency. It must canonically
  reload the full verified infrastructure/deploy/bootstrap/final-health/
  Manager/post-Manager chain, immutable unconsumed monitoring-stack
  authorization, current source/catalog/controller files, and unchanged
  `IN_PROGRESS/VERIFY` journal before every effect.
  Derive only the exact authorized mapping-position-fifteen monitoring stable
  ID, Ubuntu 24.04 architecture, digest-pinned official Scylla Monitoring
  4.16.0 archive/component/source provenance, install-only variables, and
  anchored command. Caller targets, versions, archives, components, auth,
  targets, binds, variables, commands, paths, results, and retry controls are
  forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-monitoring-stack-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-monitoring-stack-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-monitoring-stack-{execution,evidence}.json`.
  Record retry-safe `prepared`, then durable `started` immediately before the
  sole controlled call; `started` consumes the whole immutable authorization
  without rewriting it. Invoke only hash-checked `monitoring-stack`, exact one
  target, serial one, with registry check mode disabled. Require exact target,
  archive, component, source, command, and provenance parity,
  installed-or-no-change success, disabled/inactive Docker, listen policy
  `not-started`, and absent Docker installation/image pull, Compose/auth/target
  generation, containers/service starts, public binds, Manager registration,
  Scylla start, and secrets. Exit zero alone is insufficient and semantic
  evidence must precede terminal success.
  Once started, crash, timeout, interruption, unreachable/nonzero or malformed
  execution, semantic mismatch, drift, or persistence uncertainty is
  manual-recovery/no-retry and forbids replay, skip, continuation, or rollback.
  Exact prepared recovery is allowed only before invocation; exact complete
  re-entry is zero-process/zero-write. Keep authorization, reconciliation,
  plans, and common journal unchanged at VERIFY. Records and reports retain
  only bounded schemas, digests, counts, enums, booleans, and the permitted
  stable ID; omit addresses, provider IDs, routes, archive URLs, file paths,
  auth/configuration values, commands, variables, environments, raw output,
  protected paths, credentials, and secrets. This owner must not reconcile or
  authorize later work, generate targets/auth/Compose, start containers or
  services, finalize, or add CLI/public wiring.
- The internal post-`monitoring-stack` result reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must canonically reload and revalidate the full
  verified infrastructure/deploy/bootstrap/final-health/Manager/post-Manager
  chain, exact monitoring authorization/execution/evidence, source/catalog,
  and unchanged `IN_PROGRESS/VERIFY` journal. Require exact terminal success,
  consumed execution authorization, one complete unique installed-or-no-change
  Scylla Monitoring 4.16.0 result for the canonical monitoring target, exact
  archive/component/source/command provenance, disabled/inactive Docker,
  listen policy `not-started`, and every Docker/image-pull/Compose/auth/target/
  container/start/public-bind/Manager/Scylla/secret action absent. Incomplete,
  uncertain, recovery-required, stale, conflicting, or drifted state fails
  before persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-monitoring-stack-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-monitoring-stack-reconciliation.json`.
  Recompute and preserve the historical 21-position mapping, mark only the
  exact mapped `monitoring-stack` evidence-bound succeeded, and evaluate only
  the immediate next active gate. Read-only work may become `eligible`;
  mutating work may become only `evidence-ready-authorization-required`; never
  leapfrog, generate targets/auth/Compose, or infer stack health, readiness, or
  listeners. Exact reuse is zero-write and conflicts fail closed without
  overwrite, deletion, rollback, or adaptation. Keep the journal and every
  prior artifact unchanged. Records and reports retain only bounded schemas,
  digests, counts, enums, and booleans without addresses, provider IDs, routes,
  archive URLs, file paths, auth/configuration values, commands, variables,
  environments, output, protected paths, credentials, or secrets. This owner
  must not authorize or execute work, invoke a process, finalize, or add
  CLI/public wiring.
- The internal deploy `manager-agent` authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and one normalized ordinary approval proof. It
  must canonically reload the complete verified infrastructure/deploy/
  bootstrap/final-health, Manager-server, monitoring-stack/post-monitoring,
  storage/install/configuration, source/catalog, current Scylla inventory/
  trust/readiness, and unchanged `IN_PROGRESS/VERIFY` journal chain.
  Derive only active mapping-position-sixteen `manager-agent` instances whose
  exact status is `evidence-ready-authorization-required`, with scope equal to
  the complete canonical Scylla stable-ID set. Bind mutating classification,
  exact Ubuntu 24.04 architecture and successful current Scylla-install
  provenance, Manager 3.12 `scylla-manager-agent` package/repository/
  authenticated signing-key/source/variable/command intent, and required
  disabled/inactive service state. Configuration, token, helper-slice setup,
  server reachability, and service start must remain forbidden or
  not-performed.
  Require ordinary interactive or PLAN-permitted `cli-yes`; destructive and
  narrow proofs are inapplicable. Persist independently versioned immutable
  owner-only
  `deploy-scylla-vms.ansible-deploy-manager-agent-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-manager-agent-authorization.json`.
  Exact reuse is zero-write; changed proof, scope, or provenance requires a new
  operation. Authorization remains unconsumed and execution unavailable, and
  the journal and prior records remain unchanged. Records and reports retain
  only bounded schemas, digests, counts, enums, booleans, and permitted stable
  IDs; omit addresses, provider IDs, routes, repository URLs, key/token/
  configuration/server values, commands, variables, environments, paths,
  prompts/free text, credentials, and secrets. This owner must not invoke a
  runner, configure or start the agent, create execution records, reconcile
  later work, change the journal, finalize, or add CLI/public wiring.
- The internal deploy `manager-agent` execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its supported toolchain dependency. It must canonically
  reload the full verified infrastructure/deploy/bootstrap/final-health,
  Manager-server, monitoring-stack/post-monitoring, storage/install/
  configuration, source/catalog/controller, unconsumed authorization, and
  unchanged `IN_PROGRESS/VERIFY` journal chain before every effect.
  Derive the exact ordered complete Scylla stable-ID scope, Ubuntu 24.04
  architecture, current Scylla-install evidence, Manager 3.12
  `scylla-manager-agent` package/repository/authenticated-key provenance,
  variables, source, and anchored command internally. Caller steps, targets,
  limits, versions, packages, repositories, keys, tokens, configurations,
  server values, commands, variables, paths, results, and retry controls are
  forbidden. Invoke only hash-checked `manager-agent`, serial one and one target
  per call.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-manager-agent-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-manager-agent-evidence/v1` only at the
  canonical operation paths. Record retry-safe `prepared`, then durable
  `started` immediately before each call; first `started` consumes the whole
  authorization without rewriting it. Require exact strict installed/no-change
  evidence, disabled/inactive service, and configuration/token/helper/setup/
  server-reachability/start behavior absent or not performed before evidence
  and terminal success.
  Once started, crash, timeout, interruption, unreachable/nonzero or malformed
  execution, semantic mismatch, drift, or post-call persistence uncertainty is
  manual-recovery/no-retry and forbids replay, skip, continuation, or rollback.
  Exact prepared recovery is allowed only before invocation, an exact succeeded
  prefix may continue in immutable order, and completed re-entry is
  zero-process/zero-write. Keep the authorization, post-monitoring
  reconciliation, plans, and common journal unchanged at VERIFY. Records and
  reports retain only bounded schemas, digests, counts, enums, booleans, and
  permitted stable IDs; omit addresses, provider IDs, routes, repository URLs,
  key/token/configuration/server values, commands, variables, environments,
  raw output, protected paths, credentials, and secrets. This owner must not
  reconcile later work, write tokens/configuration, run setup, contact Manager,
  start the agent, finalize, or add CLI/public wiring.
- The internal post-`manager-agent` result reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must canonically reload and revalidate the full
  verified infrastructure/deploy/bootstrap/final-health, Manager-server,
  monitoring-stack, storage/install/configuration, exact Manager-agent
  authorization/execution/evidence, source/catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal chain.
  Require consumed terminal-success execution and complete unique ordered
  semantic evidence for every authorized Scylla stable ID, with exact Manager
  3.12 package/repository/key/source/command provenance, installed-or-no-change
  state, disabled/inactive service, and configuration/token/helper/setup/server
  reachability/start behavior absent or not performed. Prepared, started,
  failed, uncertain, recovery-required, missing, extra, duplicate, wrong-target,
  stale, or drifted state fails before persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-manager-agent-reconciliation/v1` only
  at the canonical operation path. Recompute and preserve the historical
  21-position mapping, mark only exact mapped `manager-agent` instances
  evidence-bound succeeded with bounded changed/no-change counts, and evaluate
  only the immediate next active mapped gate. Read-only work may become
  `eligible`; mutating work may become only
  `evidence-ready-authorization-required`. Exact reuse is zero-write and
  conflicts fail closed without overwrite, deletion, rollback, or adaptation.
  Keep the journal and every prior artifact unchanged. Records and reports
  retain only bounded schemas, digests, counts, enums, and booleans; omit
  addresses, provider IDs, routes, repository URLs, key/token/configuration/
  server values, commands, variables, environments, output, protected paths,
  credentials, and secrets. This owner must not authorize or execute work,
  invoke a process, configure tokens or agents, infer Manager reachability or
  health, finalize, or add CLI/public wiring.
- The internal deploy `monitoring-agent` authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and one normalized ordinary approval proof. It
  must canonically reload the complete verified infrastructure/deploy/
  bootstrap/final-health, Manager-server, monitoring-stack, Manager-agent,
  storage/install/configuration, source/catalog, current Scylla inventory/
  trust/readiness, and unchanged `IN_PROGRESS/VERIFY` journal chain through
  exact post-Manager-agent reconciliation.
  Derive only active mapping-position-seventeen `monitoring-agent` instances
  whose exact status is `evidence-ready-authorization-required`, with scope
  equal to the complete canonical Scylla stable-ID set. Bind mutating
  classification, exact Ubuntu 24.04 architecture and current successful
  Scylla-install provenance, exact ScyllaDB 2026.2 `scylla-node-exporter`
  package/repository/authenticated signing-key/source/variable/command intent,
  disabled/inactive service state, and listen policy `not-started`.
  Configuration, process-exporter, monitoring-stack installation, target
  generation, Manager registration, exporter or Scylla startup, listeners,
  and secrets must remain forbidden or not-performed.
  Require ordinary interactive or PLAN-permitted `cli-yes`; destructive and
  narrow proofs are inapplicable. Persist independently versioned immutable
  owner-only
  `deploy-scylla-vms.ansible-deploy-monitoring-agent-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-monitoring-agent-authorization.json`.
  Exact reuse is zero-write; changed proof, scope, or provenance requires a new
  operation. Authorization remains unconsumed and execution unavailable, and
  the journal and prior records remain unchanged. Records and reports retain
  only bounded schemas, digests, counts, enums, booleans, and permitted stable
  IDs; omit addresses, provider IDs, routes, repository URLs, key/
  configuration/port values, commands, variables, environments, paths,
  prompts/free text, credentials, and secrets. This owner must not invoke a
  runner, install/configure/start an exporter, create execution records,
  reconcile later work, change the journal, finalize, or add CLI/public wiring.
- The internal deploy `monitoring-agent` execution owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable pair with its supported toolchain dependency. It must canonically
  reload the complete verified infrastructure/deploy/bootstrap/final-health,
  Manager-server, monitoring-stack, Manager-agent/post-Manager-agent,
  storage/install/configuration, source/catalog/controller, unconsumed
  authorization, and unchanged `IN_PROGRESS/VERIFY` journal chain before every
  effect.
  Derive the exact ordered complete Scylla stable-ID scope, Ubuntu 24.04
  architecture, current Scylla-install evidence, and ScyllaDB 2026.2
  `scylla-node-exporter` package/repository/authenticated-key provenance,
  variables, source, and anchored command internally. Caller steps, targets,
  limits, versions, packages, repositories, keys, configuration, ports,
  commands, variables, paths, results, and retry controls are forbidden.
  Invoke only hash-checked `monitoring-agent`, serial one and one target per
  call.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-monitoring-agent-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-monitoring-agent-evidence/v1` only at the
  canonical operation paths. Record retry-safe `prepared`, then durable
  `started` immediately before each call; first `started` consumes the whole
  authorization without rewriting it. Require exact strict installed/no-change
  evidence, disabled/inactive service, listen policy `not-started`, and
  configuration/process-exporter/stack/targets/registration/exporter-or-Scylla
  startup/listener/secret behavior absent or not performed before evidence and
  terminal success.
  Once started, crash, timeout, interruption, unreachable/nonzero or malformed
  execution, semantic mismatch, drift, or post-call persistence uncertainty is
  manual-recovery/no-retry and forbids replay, skip, continuation, or rollback.
  Exact prepared recovery is allowed only before invocation, an exact succeeded
  prefix may continue in immutable order, and completed re-entry is
  zero-process/zero-write. Keep the authorization, post-Manager-agent
  reconciliation, plans, and common journal unchanged at VERIFY. Records and
  reports retain only bounded schemas, digests, counts, enums, booleans, and
  permitted stable IDs; omit addresses, provider IDs, routes, repository URLs,
  key/configuration/port values, commands, variables, environments, raw output,
  protected paths, credentials, and secrets. This owner must not reconcile
  later work, bind ports, write configuration or targets, start exporters or
  stacks, finalize, or add CLI/public deploy wiring.
- The internal post-`monitoring-agent` result reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It canonically reloads the complete verified
  infrastructure/deploy/bootstrap/final-health, Manager-server,
  monitoring-stack, Manager-agent, storage/install/configuration, exact
  Monitoring-agent authorization/execution/evidence, source/catalog, and
  unchanged `IN_PROGRESS/VERIFY` journal chain.
  Require consumed terminal-success execution and complete unique ordered
  semantic evidence for every authorized Scylla stable ID, with exact ScyllaDB
  2026.2 exporter package/repository/key/source/command provenance,
  installed-or-no-change state, disabled/inactive service, listen policy
  `not-started`, and configuration/process-exporter/stack/targets/registration/
  startup/listener/secret behavior absent or not performed. Prepared, started,
  failed, uncertain, recovery-required, missing, extra, duplicate, wrong-target,
  stale, or drifted state fails before persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-monitoring-agent-reconciliation/v1`
  only at the canonical operation path. Recompute and preserve the historical
  21-position mapping, mark only exact mapped `monitoring-agent` instances
  evidence-bound succeeded with bounded changed/no-change counts, and evaluate
  only the immediate next active mapped gate. Read-only work may become
  `eligible`; mutating work may become only
  `evidence-ready-authorization-required`. Exact reuse is zero-write and
  conflicts fail closed without overwrite, deletion, rollback, or adaptation.
  Keep the journal and every prior artifact unchanged. Records and reports
  retain only bounded schemas, digests, counts, enums, and booleans; omit
  addresses, provider IDs, routes, repository URLs, key/configuration/port
  values, commands, variables, environments, output, protected paths,
  credentials, and secrets. This owner must not authorize or execute work,
  invoke a process, configure targets, infer exporter or stack reachability or
  health, finalize, or add CLI/public wiring.
- The internal deploy `monitoring-targets` authorization owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and one normalized ordinary approval proof. It
  must canonically reload the complete verified infrastructure/deploy/
  bootstrap/final-health, Manager-server, monitoring-stack, Manager-agent,
  Monitoring-agent, storage/install/configuration, source/catalog, and
  unchanged `IN_PROGRESS/VERIFY` journal chain through exact
  post-`monitoring-agent` reconciliation.
  Derive only the active mapping-position-eighteen `monitoring-targets`
  instance whose exact status is `evidence-ready-authorization-required`, with
  scope equal to the single canonical monitoring stable ID. Bind mutating
  classification, exact Ubuntu 24.04 architecture and current successful
  base-OS, Scylla Monitoring 4.16.0 stack, Manager-server, Manager-agent, and
  Monitoring-agent evidence. Rebuild only the deterministic official four-file
  target intent from canonical RFC 1918 inventory: one Manager target and the
  complete Scylla set for Scylla, node-exporter, and Manager-agent targets.
  Persist only file-set/content, target-set, identity, variable, command,
  source, catalog, and provenance digests plus bounded counts; never persist
  file names, paths, contents, labels, addresses, ports, provider IDs, routes,
  auth/configuration values, commands, variables, environments, prompts/free
  text, credentials, or secrets.
  Require ordinary interactive or PLAN-permitted `cli-yes`; destructive and
  narrow proofs are inapplicable. Approval never bypasses role, target-set,
  RFC 1918, base-OS, stack-version, inactive/not-started service, trust,
  readiness, source, ordering, or drift gates. Persist independently versioned
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-monitoring-targets-authorization/v1` only
  at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-monitoring-targets-authorization.json`.
  Exact reuse is zero-write; changed proof, scope, intent, or provenance
  requires a new operation. Authorization remains unconsumed, execution
  unavailable, finalization not started, public workflow unavailable, and the
  common journal and prior artifacts unchanged. This owner must not invoke a
  runner/toolchain, write target files, start exporters/stacks/services,
  create execution records, reconcile later work, finalize, or add CLI/public
  deploy wiring.
- The internal deploy `monitoring-targets` execution owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, a controlled runner, and an exact validated
  sibling Ansible executable pair with its supported toolchain dependency. It
  must canonically reload the full verified infrastructure/deploy/bootstrap/
  final-health, Manager-server, monitoring-stack, Manager-agent,
  Monitoring-agent, exact post-Monitoring-agent reconciliation, immutable
  unconsumed authorization, current source/catalog/controller files, and
  unchanged `IN_PROGRESS/VERIFY` journal before every effect.
  Derive the exact single monitoring stable ID, Ubuntu 24.04 architecture,
  current Monitoring 4.16.0 stack evidence, complete RFC 1918 Manager/Scylla
  identity sets, deterministic four-file target intent, variables, source,
  and anchored command internally. Caller steps, targets, limits, versions,
  identities, labels, ports, files, auth/bind values, commands, variables,
  paths, results, and retry controls are forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-monitoring-targets-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-monitoring-targets-evidence/v1` only at
  the canonical operation paths. Record retry-safe `prepared`, then durable
  `started` immediately before the sole controlled call; `started` consumes
  the whole authorization without rewriting it. Invoke only the hash-checked
  `monitoring-targets` source for that exact target, serial one, with registry
  policy. Require strict target/version/file-set/content/identity/count/source/
  command/intent/provenance parity, generated-or-no-change success, listen
  policy `not-started`, scrape readiness `not-performed`, and all Docker/
  stack/container/exporter/Manager/Scylla/auth/public-bind/Compose/secret
  behavior false or not performed. Exit zero alone is insufficient and
  semantic evidence must precede terminal success.
  Once started, crash, timeout, interruption, unreachable/nonzero or malformed
  execution, semantic mismatch, drift, or persistence uncertainty is manual-
  recovery/no-retry and forbids replay, skip, continuation, or rollback.
  Exact prepared recovery is allowed only before invocation; exact complete
  re-entry is zero-process/zero-write. Keep authorization, reconciliation,
  historical plans, and the common journal unchanged at VERIFY. Records and
  reports retain only bounded schemas, digests, counts, enums, booleans, and
  the permitted stable ID; omit addresses, provider IDs, routes, file names/
  contents, labels, ports, auth/config values, commands, variables,
  environments, raw output, protected paths, credentials, and secrets. This
  owner must not reconcile later work, start services, test scrapes, expose a
  UI, finalize, or add CLI/public deploy wiring.
- The internal post-`monitoring-targets` result reconciliation owner accepts
  only canonical state-root/cluster identity, one operation UUID, and the
  matching already-held deploy lock. It must canonically reload and revalidate
  the complete verified infrastructure/deploy/bootstrap/final-health,
  Manager-server, monitoring-stack, Manager-agent, Monitoring-agent, exact
  monitoring-targets authorization/execution/evidence, source/catalog, and
  unchanged `IN_PROGRESS/VERIFY` journal chain. Require consumed terminal
  success and one complete unique generated-or-no-change Monitoring 4.16.0
  result for the canonical monitoring target, with exact four-file
  file-set/content/identity/source/command/intent provenance, listen policy
  `not-started`, scrape readiness `not-performed`, and every Docker/stack/
  container/exporter/Manager/Scylla/auth/public-bind/Compose/secret action
  absent. Prepared, started, failed, uncertain, recovery-required, incomplete,
  stale, conflicting, or drifted state fails before persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-monitoring-targets-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-monitoring-targets-reconciliation.json`.
  Recompute and preserve the historical 21-position mapping and mark only
  mapped `monitoring-targets` evidence-bound succeeded. Evaluate only immediate
  sensitive `manager-tasks`: its explicit-action condition remains unmodeled
  and its source remains validation-only, so retain the exact action/backend/
  registration/service/health/authorization/public-workflow blockers unless
  separately reviewed evidence resolves every gate. Never invent a default
  task action, infer backup/repair readiness, invoke `sctool`, start/unmask
  Manager, configure a backend, or register a cluster. Exact reuse is
  zero-write and conflicts fail closed. Keep the journal and every prior
  artifact unchanged. Records and reports retain only bounded schemas,
  digests, counts, enums, and booleans; omit addresses, provider IDs, routes,
  file names/content, labels, ports, auth/config/task values, commands,
  variables, environments, output, protected paths, credentials, and secrets.
  This owner must not authorize or execute work, invoke a process, change the
  journal, finalize, or add CLI/public wiring.
- The internal deploy Manager-activation bridge accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. It must canonically reload and reproduce the full chain through
  exact post-`monitoring-targets` reconciliation plus current Manager-server
  and complete Manager-agent install evidence, inventory, trust, readiness,
  source, catalog, and unchanged `IN_PROGRESS/VERIFY` journal state.
  Persist separate independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-manager-activation-context/v1` then
  `deploy-scylla-vms.ansible-deploy-manager-activation-plan/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-manager-activation-{context,plan}.json`.
  Never rewrite the historical 21-position deploy context, plan, or any
  reconciliation.
  Derive the exact Manager stable ID and complete Scylla Manager-agent stable-ID
  set from canonical inventory. Model only the ordered boundaries established
  by current contracts: mutating backend configuration, mutating Manager
  service activation/readiness, sensitive cluster-registration/auth-token
  handoff, then sensitive mapped `manager-tasks` action/context. The first
  three boundaries remain source-unavailable and every boundary remains
  authorization-required, evidence-required, blocked, and not-performed.
  `manager-tasks` remains source-available but validation-only; because deploy
  supplies no deterministic explicit action, retain
  `manager-tasks-action-unmodeled` and never choose the source's default
  `inspect` action. Install-only Manager server/agent evidence must never be
  promoted to backend, service, registration, token, reachability, or task
  readiness.
  Build both records completely in memory, publish context before plan, recover
  only an exact context-only prefix, reuse exact records without writes, and
  fail every conflict, tamper, drift, ambiguous artifact, or changed provenance
  closed without overwrite, deletion, rollback, or adaptation. Keep reports
  limited to schemas, digests, counts, enums, booleans, and permitted stable
  IDs; omit addresses, provider IDs, routes, backend/token/config/task values,
  commands, variables, environments, paths, prompts/free text, credentials,
  and secrets. This bridge must not authorize, execute, invoke a runner, change
  the journal, finalize, or add CLI/public wiring.
- The internal deploy Manager backend-configuration context/plan owner accepts
  only canonical state-root/cluster identity, one operation UUID, and the
  matching already-held deploy lock. It must canonically reload and reproduce
  the exact Manager-activation context/plan, post-monitoring-targets
  reconciliation, current Manager-server and complete Manager-agent install
  evidence, final complete-set Scylla health/topology, current observation/
  inventory/trust/readiness/source/catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal before persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-configuration-context/v2`
  then
  `deploy-scylla-vms.ansible-deploy-manager-backend-configuration-plan/v2`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-manager-backend-configuration-{context,plan}.json`.
  Build both records in memory, publish context before plan, recover only an
  exact context-only prefix, reuse exact records without writes, and fail
  conflict, tamper, drift, ambiguous artifacts, or changed provenance closed.
  Derive only the versioned
  `deploy-scylla-vms.manager-backend-local-one-node-policy/v1` from canonical
  design evidence. It selects the official recommended one-node ScyllaDB
  backend on the Manager VM, forbids the managed data cluster as backend,
  forbids CQL network ingress, fixes loopback-only contact with port 9042 and
  ScyllaDB 2026.2 compatibility, and uses no backend credentials/TLS secrets
  for loopback v1. Future Manager-agent token policy remains environment-only.
  Resolve only the typed backend-mode gate. Package availability, storage/
  tuning/capacity suitability, setup behavior, backend identity/topology/
  health, exact configuration binding, schema/keyspace policy, recovery, and
  the mutating source remain typed unknown/blockers.
  Exact target/install evidence, masked/inactive Manager, final Scylla health/
  topology, canonical provenance, and source catalog are passed gates. The
  read-only `manager-backend-preflight` source is not the mutating backend
  configuration source. Never reuse it, install-only `manager-server`, or
  validation-only `manager-tasks` to write configuration. The distinct
  mutating boundary remains source-unavailable, blocked-before-authorization,
  and not-performed. Preserve the historical 21-position mapping and VERIFY
  journal. Reports retain only schemas/digests, bounded counts/enums/booleans,
  and permitted stable IDs; omit addresses, provider IDs, backend/config/auth/
  TLS/token/credential values, ports, commands, variables, environments, paths,
  prompts, and secrets. This owner
  must not authorize, execute,
  persist evidence/reconciliation, invoke a runner, write configuration, start
  Manager, register a cluster, act on tasks, change the journal, finalize, or
  add CLI/public wiring.
- The internal operation-bound Manager backend-preflight owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, a controlled runner, and an exact validated sibling
  Ansible executable pair with its supported toolchain dependency. It must
  canonically reload and revalidate the full chain through the exact
  local-one-node backend context/plan, Manager activation,
  post-monitoring-targets reconciliation, current Manager-server and complete
  Manager-agent evidence, final Scylla health, observation/inventory/trust/
  readiness/source/catalog/controller files, and unchanged
  `IN_PROGRESS/VERIFY` journal before every effect.
  Derive the single Manager target, fixed read-only variables, hash-checked
  source, and anchored command internally. Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-preflight-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-manager-backend-preflight-evidence/v1` only
  at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-manager-backend-preflight-{execution,evidence}.json`.
  Record durable `started` before the sole exact-target, serial-one,
  check-mode-safe controlled call. Require strict parser/result target, role,
  OS/architecture, source, command, provenance, and bounded host-evidence
  parity; exit zero alone is insufficient.
  Once started, crash, timeout, interruption, unreachable/nonzero or malformed
  execution, semantic mismatch, drift, or persistence uncertainty is
  manual-recovery/no-retry. Exact complete re-entry is zero-process/zero-write
  and conflicting prefixes fail closed. Evidence and reports may retain only
  the permitted stable ID, bounded role/OS/architecture/capacity/mount/status
  values, package/service/configuration/schema/reboot/loopback states, explicit
  not-performed actions, blockers, and digests; omit addresses, provider IDs,
  raw paths, package output, configuration content, commands, variables,
  environments, raw output, credentials, and secrets.
  After exact terminal success and evidence, persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-preflight-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-manager-backend-preflight-reconciliation.json`.
  Reconciliation may evaluate only later local-backend installation-planning
  gates. Package availability, storage/tuning suitability, exact capacity
  policy, setup behavior, schema/keyspace policy, recovery, and mutating-source
  requirements remain explicit unknown/blockers; backend operational readiness
  remains `not-performed`, authorization unavailable, and execution not
  started. Exact reuse is zero-write. Keep the journal and prior records
  unchanged and do not install packages, mutate storage/tuning/configuration/
  schema/services, authorize mutation, finalize, or add CLI/public wiring.
- The internal Manager local-backend installation-planning owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must canonically reload and revalidate the full
  chain through exact backend-preflight execution/evidence/reconciliation,
  local-one-node policy, Manager inventory/trust/readiness/base-OS/install
  evidence, desired/provider/observation/source/catalog, and the unchanged
  `IN_PROGRESS/VERIFY` journal.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-installation-context/v1`
  then
  `deploy-scylla-vms.ansible-deploy-manager-backend-installation-plan/v1` only
  at the canonical operation paths. Build both records in memory, publish
  context first, recover only an exact context-only prefix, reuse exact records
  without writes, and fail conflicts, tamper, drift, or ambiguous history
  closed.
  Reuse only exact Ubuntu 24.04/architecture and authenticated ScyllaDB 2026.2
  repository/key references. Derive one dedicated Manager Block Volume only
  from exact desired and Terraform-observed provider identity; retain only
  redacted digests and never select a device by order/path. When dedicated
  storage is absent or unidentifiable, record
  `dedicated-backend-storage-unmodeled`; root/boot storage and generic free
  space are never fallback capacity.
  Model package install, local storage allocation/preflight/preparation/
  postcheck, local Scylla configuration/tuning, one-node bootstrap/start/
  health, Manager backend-file configuration, and schema/keyspace creation/
  verification as separate ordered future boundaries. The exact package set,
  authenticated provenance, and source are approved only for the first
  package-install boundary; when every prerequisite and dedicated-storage gate
  passes, that step is `evidence-ready-authorization-required`. Capacity
  thresholds, storage/tuning policy, service order, configuration ownership,
  keyspace/RF/schema, recovery, and `scyllamgr_setup` behavior remain typed
  blockers. Existing Scylla-role storage/configure/bootstrap owners are
  contract-incompatible unless separately reviewed, so the remaining eight
  Manager-local sources remain unavailable.
  Preserve the historical mapping and VERIFY journal. Reports retain only
  schemas/digests, bounded counts/enums/booleans, the permitted stable ID, and
  blocker names. This owner must not authorize, execute, invoke a runner,
  mutate package/storage/configuration/schema/services, transition the journal,
  or add CLI/public wiring.
- The source-available `manager-backend-local-install` contract is mutating,
  Manager-only, exact-one-target, serial-one, fatal, and check-mode
  preview-only. It must require the exact current local-one-node backend
  installation context/plan, successful backend-preflight reconciliation,
  Manager Ubuntu 24.04/architecture/base-OS and Manager-server evidence,
  identified dedicated-backend-storage status, observation/inventory/trust/
  source provenance, and authenticated exact ScyllaDB 2026.2 package,
  repository, and signing-key provenance.
  Reuse only the reviewed seven-package `scylla-install` package facts; never
  reuse its Scylla-role identity, storage-postcheck prerequisite, or upstream
  role invocation. Prevent maintainer-script startup, mask/stop
  `scylla-server` before package work, and leave it masked/inactive. Strict
  `deploy-scylla-vms.ansible-manager-backend-local-install/v1` evidence may
  retain only the stable ID/role/OS/architecture, installed/no-change/changed
  state, exact package/version and repository/key/source/command provenance
  digests, masked/inactive service state, and explicit false/not-performed
  forbidden actions. Omit addresses, provider IDs, raw package output,
  repository URLs, key content, commands, variables, environment, paths,
  credentials, and secrets.
  Never run `scylla_setup`, `scyllamgr_setup`, tuning, storage/filesystem/mount
  mutation, configuration rendering, CQL/schema/keyspace work, Manager
  configuration/registration/tasks, Manager-agent token work, or service
  enable/start. The source contract itself performs no authorization or
  execution ownership, reconciliation, journal transition, or CLI/public
  wiring.
- The internal operation-bound Manager local-backend package-install
  authorization owner accepts only canonical state-root/cluster identity, one
  operation UUID, the matching already-held deploy lock, and an
  already-normalized ordinary approval proof. It must canonically reload and
  reproduce the full chain through the selected local-one-node backend
  context/plan, preflight execution/evidence/reconciliation, current
  installation context/plan, exact Manager target/base-OS/Manager-server
  evidence, observation/inventory/trust/readiness, package source/hash/
  provenance, catalog, and unchanged `IN_PROGRESS/VERIFY` journal.
  Derive only the exact package-install step when it is
  `evidence-ready-authorization-required`. An immutable plan that predates or
  conflicts with current source/catalog must fail closed and require a new
  operation; never rewrite or adapt it. Bind exact target, Ubuntu
  24.04/architecture, ScyllaDB 2026.2 package set, official repository and
  authenticated signing key, source/variable/command intent, and
  masked/inactive package-only policy through bounded values and digests.
  Require ordinary interactive or PLAN-permitted `cli-yes` approval.
  Destructive proof/flags and narrow consent are inapplicable and refused;
  approval never bypasses preflight, dedicated-storage identity, platform,
  base-OS/Manager evidence, source/catalog, inactive-service, ordering, or
  drift gates.
  Persist immutable owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-local-install-authorization/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-manager-backend-local-install-authorization.json`.
  Exact reuse is zero-write; changed proof, scope, or provenance requires a new
  operation. Authorization remains unconsumed, execution unavailable, and the
  journal and prior records unchanged. Records and reports retain only bounded
  schemas/digests/counts/enums/booleans and the permitted stable ID; omit
  addresses, provider IDs, device paths, repository URLs, key content,
  commands, variables, environments, paths, prompts/free text, credentials,
  and secrets. This owner must not invoke a runner, install packages, create
  execution/evidence/reconciliation records, advance a later boundary, change
  the journal, or add CLI/public wiring. The next ordered slice is the
  operation-bound package-install execution owner.
- The internal operation-bound Manager local-backend package-install execution
  owner accepts only canonical state-root/cluster identity, one operation UUID,
  the matching already-held deploy lock, a controlled runner, and an exact
  validated sibling Ansible executable pair with its supported toolchain
  dependency. It must canonically reload and reproduce the complete chain
  through the local-one-node backend context/plan, successful preflight
  execution/evidence/reconciliation, installation context/plan, exact
  unconsumed authorization, Manager target/base-OS/Manager-server evidence,
  observation/inventory/trust/readiness/source/catalog/controller files, and
  unchanged `IN_PROGRESS/VERIFY` journal before every effect.
  Derive the sole Manager target, Ubuntu 24.04 architecture, exact authenticated
  ScyllaDB 2026.2 seven-package set, repository/signing-key provenance,
  dedicated-storage identity binding, package-only variables, hash-checked
  source, and anchored command internally. Caller targets, packages, versions,
  repositories, keys, commands, variables, paths, results, and retry controls
  are forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-local-install-execution/v1`
  and immutable-prefix
  `deploy-scylla-vms.ansible-deploy-manager-backend-local-install-evidence/v1`
  only at the canonical operation paths. Record retry-safe `prepared` after full
  validation and durable `started` immediately before the sole controlled call;
  `started` consumes authorization without rewriting it. Require strict exact
  target/package/version/repository/key/source/command/provenance evidence,
  installed-or-no-change success, masked/inactive `scylla-server`, and every
  setup/tuning/storage/configuration/schema/CQL/Manager configuration/service/
  registration/task action false or not-performed; exit zero alone is
  insufficient and semantic evidence must precede terminal success.
  Once started, crash, timeout, interruption, unreachable/nonzero or malformed/
  non-UTF-8/oversized execution, semantic mismatch, drift, or post-call
  persistence failure is manual-recovery/no-retry and forbids rollback,
  continuation, or replay. Exact prepared recovery is allowed only before
  invocation; exact completed re-entry is zero-process/zero-write. Keep the
  authorization, plans, journal, and all prior artifacts unchanged. Records and
  reports retain only bounded schemas/digests/counts/enums/booleans and the
  permitted stable ID; omit addresses, provider IDs, device paths, repository
  URLs, key content, commands, variables, environments, raw output, protected
  paths, credentials, and secrets. This owner must not reconcile the result,
  prepare storage, configure/tune/start Scylla, run setup scripts, advance a
  later boundary, change the journal, or add CLI/public wiring.
- The internal post-Manager-local-package reconciliation owner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It must canonically reload and reproduce the full
  chain through the selected local-one-node backend context/plan, successful
  preflight execution/evidence/reconciliation, installation context/plan,
  exact package authorization/execution/evidence, Manager target/base-OS/
  Manager-server evidence, current observation/inventory/trust/readiness/
  source/catalog, and unchanged `IN_PROGRESS/VERIFY` journal.
  Require exact terminal-success execution with consumed authorization and one
  complete unique semantic result: exact target/platform and ScyllaDB 2026.2
  package/repository/key/source/command provenance, installed or no-change,
  masked/inactive `scylla-server`, and every setup/tuning/storage/
  configuration/schema/CQL/Manager configuration/service/registration/task
  action false or not-performed. Prepared, started, failed, uncertain,
  manual-recovery, missing, extra, wrong-target, stale, or drifted state fails
  before persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-manager-backend-local-install-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-manager-backend-local-install-reconciliation.json`.
  Recompute and preserve every immutable installation-plan boundary, order,
  and identity digest; mark only package install evidence-bound succeeded with
  bounded changed/no-change evidence. Evaluate only the immediate next
  plan-derived boundary: read-only work may become eligible and mutating work
  may become only evidence-ready-authorization-required when all gates and an
  exact source are available. The immutable reconciliation's
  `local-storage-allocation` remains blocked by its recorded unavailable
  Manager-local source/contract, unknown capacity policy, and the
  contract-incompatible Scylla-role storage owner. Keep
  capacity, tuning, setup, configuration, schema, and recovery gates unknown
  or blocked and never leapfrog.
  Exact reuse is zero-write and conflicts fail closed without overwrite,
  deletion, rollback, or adaptation. Keep the journal, plans, and every prior
  record unchanged. Records and reports retain only bounded schemas/digests/
  counts/enums/booleans, the permitted stable ID, and blocker names; omit
  addresses, provider IDs, device paths/serials, repository URLs, key content,
  commands, variables, environment, output, protected paths, credentials, and
  secrets. This owner must not authorize or execute work, invoke a runner,
  mutate storage/configuration/services, change the journal, finalize, or add
  CLI/public wiring. This reconciliation remains immutable and blocked; later
  planning records must not rewrite or reinterpret it.
- The internal Manager-backend storage allocation/discovery planning owner
  accepts only canonical state-root/cluster identity, one operation UUID, and
  the matching already-held deploy lock. It must canonically reload and
  revalidate the complete chain through exact post-package reconciliation,
  Manager backend policy/installation plans, Manager target/package evidence,
  current desired/Terraform input/observation/inventory/trust/readiness,
  source/catalog, and unchanged `IN_PROGRESS/VERIFY` journal.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-allocation-context/v1`
  then
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-allocation-plan/v1`
  only at the canonical operation paths. Build both records in memory, publish
  context first, recover only an exact context-only prefix, reuse exact records
  without writes, and fail conflict, tamper, drift, ambiguous history, or
  changed provenance closed. Caller devices, paths, sizes, actions, commands,
  variables, targets, capacity decisions, and authorization are forbidden.
  Derive only one dedicated Manager-role Block Volume with exact stable/provider
  identity and matching Terraform storage-manifest attachment. Root/boot
  fallback, local NVMe, arbitrary attachments, path/order selection, and shared
  Scylla-role storage are forbidden. A missing, ambiguous, or path-only
  allocation remains blocked with no discovery target. The allocation record
  may retain only bounded requested/observed GiB, count/backend states, and
  redacted identity/manifests/provenance digests. Capacity policy stays
  `unknown` and adequacy `not-evaluated`; allocation identity is not capacity
  approval. An exact allocation with a non-path guest identity and current
  source may produce only one read-only discovery target. Keep post-package
  reconciliation, installation plans, journal, authorization, execution,
  evidence, mutation, finalization, and CLI/public behavior unchanged.
- The source-available `manager-backend-storage-discover` contract is read-only,
  Manager-only, exact-one-target, serial-one, fatal, and check-mode-safe. It
  requires the exact current storage-allocation context/plan, Manager target,
  desired/Terraform input/observation/inventory/trust/readiness, dedicated
  Block Volume manifest, source, and catalog provenance. Inspect only bounded
  Linux block, mount, signature, holder, ownership-marker, and topology facts
  needed to match the exact manifest through non-path identities. Refuse
  missing, ambiguous, root/boot, local-NVMe, mounted, held, shared, wrong-size,
  or manifest/provenance-conflicting candidates.
  Strict
  `deploy-scylla-vms.ansible-manager-backend-storage-discovery/v1` results may
  retain only the stable ID, bounded device count/size/type/signature/
  ownership/status enums, blockers, and hashed device/topology/manifest/
  provenance digests. Omit raw paths, serials, UUIDs, addresses, provider IDs,
  commands, variables, environment, raw output, credentials, and secrets.
  Never write, wipe, partition, create RAID/filesystems, mount, edit fstab,
  configure or start services, access CQL, authorize work, transition the
  journal, or add CLI/public wiring.
- The internal operation-bound Manager backend storage-discovery execution
  owner accepts only canonical state-root/cluster identity, one operation UUID,
  the matching already-held deploy lock, a controlled runner, and an exact
  validated sibling Ansible executable pair with its supported toolchain
  dependency. It must reload the full chain through local-one-node backend
  plans, preflight, package reconciliation, and exact storage-allocation
  context/plan plus current desired/provider input/observation/inventory/trust/
  readiness/source/catalog/controller/journal state before every effect.
  Derive only the sole Manager target, exact dedicated Block Volume manifest
  and non-path identity-bound variables, hash-checked source, and anchored
  command. Refuse absent, ambiguous, root/boot, local-NVMe, shared, arbitrary,
  or path-only storage before invocation.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-execution/v1`
  and immutable-prefix
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-evidence/v1`
  only at the canonical operation paths. Record durable `started` before the
  sole exact-one-target, serial-one, check-mode-safe controlled call. Require
  exact target/role/manifest/source/command/provenance and complete unique
  device semantics; exit zero alone is insufficient. Evidence retains only
  bounded count/size/type/signature/ownership/status values and hashed device/
  topology/manifest/provenance identities. Omit raw paths, serials, UUIDs,
  addresses, provider IDs, commands, output, environment, credentials, and
  secrets.
  Once started, crash, timeout, interruption, unreachable/nonzero or malformed
  execution, semantic mismatch, drift, or persistence uncertainty is
  manual-recovery/no-retry. Exact completed re-entry is zero-process/zero-write
  and conflicts fail closed.
  The subprocess-free reconciliation owner persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-reconciliation/v1`
  only at the canonical operation path after exact terminal success and
  evidence. Mark only strict discovered evidence succeeded; bounded blocked
  evidence remains blocked. Evaluate only the immediate capacity/storage-
  preflight planning boundary. Capacity adequacy remains unknown unless a
  separately approved exact policy exists; storage preflight/preparation,
  authorization, wipe safety, and owned-noop remain unavailable, not-performed,
  or not-inferred. Keep the common journal and all prior records unchanged at
  `IN_PROGRESS/VERIFY`. These owners must not mutate storage, authorize work,
  run storage preflight/preparation, configure/start services, finalize, or add
  CLI/public wiring.
- The internal Manager-backend dedicated-storage preflight planning owner
  accepts only canonical state-root/cluster identity, one operation UUID, and
  the matching already-held deploy lock. It must canonically reload and
  revalidate the complete local-one-node backend, host-preflight, package,
  allocation, successful storage-discovery reconciliation, Manager target,
  desired/Terraform manifest, hashed guest-device evidence, source/catalog,
  and unchanged `IN_PROGRESS/VERIFY` journal chain.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-context/v1`
  then
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-plan/v1`
  only at the canonical operation paths. Build both records in memory, publish
  context first, recover only an exact context-only prefix, reuse exact records
  without writes, and fail every conflict, tamper, drift, ambiguity, or
  provenance change closed. Caller devices, paths, actions, layouts, capacity
  decisions, commands, variables, targets, and free text are forbidden.
  Approve only one whole dedicated Manager Block Volume, XFS, fixed
  `/var/lib/scylla` ownership boundary, required fstab/mount intent, and the
  Manager-local one-node marker. RAID, partitions, local NVMe, root/boot
  fallback, arbitrary attachments, and shared Scylla-role storage are
  forbidden. Require exact desired, Terraform-observed, and discovered device
  GiB/count/type plus current manifest/device identity equality. This proves
  only operator-selected allocation conformance; retain long-term operational
  capacity sufficiency as `not-proven` and operator-policy-bound.
- The source-available `manager-backend-storage-preflight` contract is
  read-only, Manager-only, exact-one-target, serial-one, fatal, and
  check-mode-safe. It requires the exact immutable preflight context/plan,
  successful storage discovery reconciliation, Manager target, desired/
  Terraform input/observation/inventory/trust/readiness/source/catalog
  provenance, and strict internally derived variables. Reconcile only bounded
  current block, signature, holder, root/boot, mount, fstab, filesystem,
  ownership-marker, and topology facts. Classify only `owned-noop`,
  `prepare-required`, or `blocked`, with exact bounded actions.
  An exact blank unowned device may be prepare-required without wipe. Existing
  signatures on an otherwise exact unowned device are foreign, block
  preparation, and report a separate future wipe requirement. Absence alone
  never proves wipe safety. Foreign ownership, unexpected mount/fstab/marker
  state, root/boot ancestry, holders, partitions, ambiguity, or identity/size/
  topology mismatch blocks.
  Strict
  `deploy-scylla-vms.ansible-manager-backend-storage-preflight/v1` results may
  retain only stable ID, bounded backend/layout/capacity/disposition/action
  enums, booleans, counts, blockers, and hashed device-set/preparation-intent/
  provenance digests. Omit raw paths, serials, UUIDs, addresses, provider IDs,
  commands, variables, output, environment, credentials, and secrets.
  Never write, wipe, partition, create RAID/filesystems, mount, edit fstab,
  write markers, configure or start services, run setup or CQL, authorize
  mutation, transition the journal, or add CLI/public wiring.
- The internal operation-bound Manager backend storage-preflight owner accepts
  only canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, a controlled runner, and an exact validated sibling
  Ansible executable pair with its supported toolchain dependency. It must
  canonically reload and revalidate the complete local-backend, host-preflight,
  package, allocation/discovery execution/evidence/reconciliation, immutable
  storage-preflight context/plan, exact Manager target, desired/Terraform
  manifest, hashed guest-device evidence, source/catalog/controller/toolchain,
  and unchanged `IN_PROGRESS/VERIFY` journal chain before every effect.
  Derive only the exact one target and strict desired-policy/manifest/discovery
  projection, hash-checked source, variables, and anchored command. Caller
  targets, devices, paths, actions, layouts, capacity decisions, evidence,
  commands, variables, results, and retry controls are forbidden.
  Persist generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-execution/v1`
  and immutable-prefix
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-evidence/v1`
  only at the canonical operation paths. Record durable `started` before the
  sole exact-one-target, serial-one, check-mode-safe controlled call. Require
  exact target/policy/manifest/discovery/source/command/provenance and complete
  unique disposition/action evidence; exit zero alone is insufficient.
  Evidence retains only stable ID, bounded backend/layout/capacity values,
  desired/manifest/discovery digests, disposition/action enums, hashed device
  sets, blocker/status/preparation-intent digests, and wipe booleans. Omit raw
  paths, serials, UUIDs, addresses, provider IDs, commands, variables, output,
  environment, credentials, and secrets.
  Once started, crash, timeout, interruption, unreachable/nonzero or malformed/
  non-UTF-8/oversized execution, semantic mismatch, drift, or persistence
  uncertainty is manual-recovery/no-retry. Exact completed re-entry is
  zero-process/zero-write and conflicts fail closed.
  The subprocess-free reconciliation owner persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-reconciliation/v1`
  only after exact terminal success and evidence. Mark preflight succeeded;
  keep `owned-noop` not-required and never authorized; preserve blocked
  evidence; and derive only exact `prepare-required` stable-ID/disposition/
  device-set/preparation-intent scope, with the wipe-required target and scope
  digests separate. Capacity sufficiency remains `not-proven` and must never
  satisfy later service-health/capacity gates. Exact prepare-required scope is
  evidence-ready-authorization-required with source available, while storage
  preparation authorization/execution, postcheck, mutation, configuration/service work,
  the common journal, finalization, and CLI/public wiring unavailable or
  unchanged. Exact reconciliation reuse is zero-write and conflicts fail
  closed.
- The source-available `manager-backend-storage-prepare` contract is
  destructive, Manager-only, exact-one-target, serial-one, fatal, and
  check-mode-refused. It requires the exact current preflight reconciliation
  and prepare-required scope, successful package evidence with Scylla masked/
  inactive, current desired/manifest/discovery/preflight/device-set/
  preparation-intent/source provenance, and typed operation/node
  authorization inputs. Immediately before its first write, revalidate hashed
  device identity, signatures, ownership, busy state, root/boot ancestry,
  mount/fstab state, and exact requested/observed/discovered allocation
  conformance.
  Its only actions are the reviewed single whole-device XFS boundary: optional
  separately authorized wipe only for an exact preflight wipe-required scope,
  XFS creation, stable UUID fstab entry, `/var/lib/scylla` mount, exact root
  ownership/mode, and Manager-local ownership marker/provenance. Generic
  approval never supplies wipe consent. Never wipe blank, `owned-noop`,
  retained, root/boot, local-NVMe, foreign-owned, ambiguous, or blocked
  devices. RAID, LVM, partitions, tuning, package work, Scylla/Manager
  configuration, service enable/start, CQL/schema/setup/registration/tasks are
  forbidden.
  Strict
  `deploy-scylla-vms.ansible-manager-backend-storage-prepare/v1` results retain
  only stable ID, bounded action/disposition/status/count values, hashed
  device/provenance/intent identities, wipe/mutation/recovery booleans,
  XFS/fstab/mount/marker/ownership verification, and explicit not-performed
  actions. Omit raw paths, serials, UUIDs, addresses, provider IDs, commands,
  variables, output, environment, credentials, and secrets. The source
  contract itself owns no operation authorization/execution persistence,
  reconciliation, journal transition, CLI/public wiring, or automatic retry.
- The source-available `manager-backend-preflight` contract is read-only,
  manager-only, exact-one-target, serial-one, fatal, and check-mode-safe. It
  requires current Manager Ubuntu 24.04/architecture/base-OS, install-only
  Manager 3.12 evidence, exact activation/backend policy and plan, and current
  inventory/trust/readiness/source provenance. Inspect only exact OS/
  architecture, bounded CPU/memory/root capacity, approved-mount availability
  and counts, fixed local Scylla/Manager package and service states, reboot
  requirement, and loopback availability. Never collect environment/process
  commands, query repositories, read configuration content, expose raw device
  paths, access metadata/cloud services, connect to a network/CQL/schema, or
  mutate packages/configuration/schema/services.
  Strict `deploy-scylla-vms.ansible-manager-backend-preflight/v1` results may
  retain only stable ID, role, bounded capacities/counts, status enums,
  provenance digests, explicit not-performed actions, and bounded blockers;
  omit addresses, provider IDs, raw paths, package output, commands,
  configuration, credentials, and secrets. `evidence-ready` means only ready
  for later reviewed local-backend installation planning. Package availability,
  storage/tuning suitability, capacity policy, setup behavior, schema/keyspace
  policy, and recovery remain blockers; backend operational readiness is
  `not-performed`. Keep package installation, `scyllamgr_setup`, configuration
  writes, schema creation, service starts, authorization, journal transitions,
  and CLI/public wiring absent from the source contract.
- Keep Terraform's plugin cache at
  `<cluster-root>/terraform/plugin-cache/`, distinct from `TF_DATA_DIR`, state,
  source work, and saved plans. Never forward ambient Terraform CLI arguments,
  variables, workspaces, proxy values, or CLI configuration.
- Security rules must be least-privilege. Do not expose SSH, ScyllaDB, Manager,
  or monitoring endpoints to the public internet by default.
- Infrastructure deletions, replacements, imports, state moves, and backend
  migrations require a reviewed plan, identity/drift checks, explicit operator
  intent, and appropriate recovery/backup notes.
- Unit and normal CI tests must not authenticate to OCI or modify real
  infrastructure. Live tests must be separately gated, isolated, tagged,
  budgeted, and verified for teardown.

## Ansible

- The internal controller contract accepts stable ansible-core
  `>=2.17.0,<2.21.0`; development tooling accepts ansible-lint `>=25,<27` and
  yamllint `>=1.35,<2`, with ansible-core 2.20+ required on Python 3.14. Probe
  both `ansible-playbook --version` and
  `ansible-inventory --version` through the controlled runner. Use
  `ansible-lint scylla_vms/ansible/content tests/fixtures/ansible` and
  `yamllint scylla_vms/ansible/content tests/fixtures/ansible` when YAML exists.
- Package project Ansible support under `scylla_vms/ansible/content/`; render
  `ansible.cfg` only to `<cluster-root>/ansible/ansible.cfg`, keep controller
  home/temp/cache/control data under `<cluster-root>/ansible/`, and write the
  Ansible log only below `<cluster-root>/logs/`. Production catalog entries must
  remain `source_available=false` until their reviewed bodies and exact
  dependencies exist. The read-only `inventory-preflight`, `connectivity-check`,
  candidate-only `routed-keyscan`, `evidence-collect`, Scylla-only
  `storage-discover`, and narrowly mutating
  `base-os` and deployment-only `deploy-reboot` entries plus the storage
  preflight/prepare/postcheck,
  `scylla-install`, `scylla-configure`, `scylla-bootstrap`,
`jump-host-configure`, `manager-agent`, `manager-server`,
`manager-backend-local-install`, `manager-backend-preflight`,
`manager-backend-storage-discover`, `manager-backend-storage-preflight`,
`manager-backend-storage-prepare`,
`manager-tasks`,
`monitoring-agent`, `monitoring-stack`, `monitoring-targets`,
`storage-retire`, `service-converge`, `scylla-cluster-shutdown`,
`os-upgrade-preflight`, `os-upgrade-in-place`,
`os-reprovision-prepare` and `os-upgrade-postcheck` sources are the currently
available sources.
 The internal `deploy-scylla-vms.ansible-operation-plan/v1` resolver is
 lock-bound and strictly offline. It may validate only registry-positioned
 conditional steps, stable-ID limits, command policy, allowlisted variables,
 current readiness, and pre-health gates. Its public projection must omit
 variable values, addresses, provider identities, keys, and paths. A ready or
 blocked plan and PLAN-phase checkpoint are not execution authorization: do not
 create runtime files, invoke the runner, persist or advance a journal, confirm,
 or mark any unimplemented public workflow available from this resolver.
 The separate strict
 `deploy-scylla-vms.ansible-operation-binding/v1` companion may be written only
 under the matching already-held operation lock at
 `<cluster-root>/operations/<operation-uuid>.ansible-operation-binding.json`.
 Keep it immutable, owner-only, atomic, and bound to exact request, plan,
 selected stable IDs, catalog, packaged source, readiness, observation,
 inventory, trust, and common-journal digests/generations. Confirmation remains
 `not-collected` and execution `not-started`. Offline resume validation may
 return only the exact unchanged PLAN checkpoint; any confirm-or-later,
 started, destructive, interrupted, failed, completed, stale, drifted,
 malformed, unknown, or ambiguous state must fail closed without advancing the
 journal, invoking a runner, or authorizing automatic retry.
 The independently versioned immutable
 `deploy-scylla-vms.ansible-operation-context/v1` companion belongs only at
 `<cluster-root>/operations/<operation-uuid>.ansible-operation-context.json`.
 Create it under the matching operation lock after the exact binding exists and
 before authorization or execution. Keep binding v1 unchanged and acyclic:
 context repeats its exact request/plan/binding/classification/target digests
 and identities plus a safe intent-context digest. The sole modeled values
 schema is currently `check-jump-hosts/v1`, with bounded stable-ID selectors,
 destination/depth enums, unique allowlisted role/port checks, and bounded
 native numeric timeouts. It must never contain addresses, probes, inventory,
 arbitrary variables, commands, environments, paths, keys, secrets, or
 protected inputs. Re-derive runtime probes from current canonical inventory,
 reconstruct the request without caller/environment input, and require the
 resolver to reproduce the bound plan. Reject unknown fields, aliases,
 coercions, duplicates, late initial creation, missing legacy context, or any
 semantic rewrite.
 The independently versioned immutable
 `deploy-scylla-vms.ansible-operation-authorization/v1` companion belongs only
 at
 `<cluster-root>/operations/<operation-uuid>.ansible-operation-authorization.json`.
 Persist it only under the matching operation lock for an exact unblocked ready
 plan and unchanged PLAN journal checkpoint. Bind operation/cluster identity,
 static/effective class, stable targets, request, plan, operation binding,
 catalog, source, readiness, observation, inventory, trust, and journal
 generations/digests. Read-only operations must not create it. Mutating and
 sensitive operations require ordinary interactive or `--yes` proof;
 destructive operations also require existing PLAN-defined class and exact
 scope acknowledgements. Keep wipe, restart, recreation, reprovision,
 decommission, and replacement proofs separate and digest-bound; `--yes` never
 supplies them. Store normalized enums/booleans/digests only, with no prompt or
 entered text, operator/terminal/environment data, values, addresses, keys,
 commands, secrets, or protected paths. Resume validation v2 requires exact
 unchanged authorization when applicable and its absence for read-only work.
 The companion leaves `deploy-scylla-vms.operation/v1` at PLAN and execution
 `not-started`; it never authorizes or invokes a runner.
 The internal `check-jump-hosts` operation-initiation owner accepts only
 canonical state-root/cluster identity, one typed UUID, exact operation kind,
 the bounded typed request, and the matching already-held operation-named
 `ClusterLock`. The caller acquires that existing lock in its established order:
 cluster-directory flock first, then canonical lock-file flock; initiation
 acquires no nested lock. Require a fully initialized cluster and current
 metadata/desired identity, refuse pending/in-progress/interrupted competitors
 and persisted cross-cluster UUID replay, and never create layout, inventory,
 trust, readiness, or controller files. Its sole write is generation 1 of the
 existing common journal at exact `IN_PROGRESS/PLAN`, with canonical operation/
 cluster identity, normalized non-secret request digest, null resume digest,
 and no evidence because plan resolution has not occurred. Preparation may make
 exactly one guarded same-phase generation-2 transition appending the resolved
 PLAN checkpoint before binding creation. Reuse only the exact untouched
 initiation record with no companion or extra history. Every request, target,
 kind, cluster, UUID, companion, active-operation, advanced-history, path,
 ownership, permission, or lock conflict fails closed without overwrite,
 rollback, or deletion. A failure before atomic publication leaves no journal;
 a durable journal remains for existing resume semantics. Keep the strict
 `deploy-scylla-vms.ansible-operation-initiation-report/v1` projection limited
 to created/reused/blocked state, operation UUID/kind/classification, explicit
 public stable-ID selectors/count, status/phase, blockers, and request/journal
 digests. This API remains internal and must not alter the public write-free
 `check-jump-hosts` workflow.
 The internal checkpoint-preparation coordinator accepts only canonical
 state-root/cluster identity, operation UUID/kind, the existing typed request
 and readiness context, the matching held operation lock, and an optional
 already-normalized authorization outcome when both class policy and context
 support require it. It must load and validate the exact current common
 `IN_PROGRESS/PLAN` journal plus metadata/desired/observation/inventory/trust/
 readiness/source/catalog state, derive context-owned intents, resolve the
 shared deterministic plan, and call the existing stores only in binding,
 context, then authorization order. Reuse only byte-identical immutable
 records. A matching binding-only or binding-plus-context prefix may continue
 before execution; every mismatch, unexpected execution record, journal/history
 drift, failed/interrupted/completed state, destructive boundary, ambiguous
 duplicate, unsafe path, or evidence/source/catalog change must fail closed
 without overwrite, deletion, rollback, or journal advancement. A later write
 failure may leave only that valid exact-request prefix. Keep the strict
 `deploy-scylla-vms.ansible-operation-preparation-report/v1` projection limited
 to stage states, schemas/digests, safe operation/stable IDs, blockers, and
 resumable-pre-execution truth. It must not accept caller plans, commands,
 variables, environments, inventory, paths, or free-form prompts; render files;
 probe tools; execute; create execution records; or add CLI/public wiring.
 Initially only context-v1-modeled `check-jump-hosts` may prepare, so
 authorization is forbidden/not-required and every other kind remains
 `operation-context-unmodeled` before writes.
 The separate strict `deploy-scylla-vms.ansible-operation-execution/v1`
 companion belongs only at
 `<cluster-root>/operations/<operation-uuid>.ansible-operation-execution.json`.
 Its internal handoff requires the matching held operation lock and canonical
 paths, immediately revalidates the exact binding/plan/catalog/source/readiness/
 observation/inventory/trust/journal/authorization checkpoint, and records at
 most one deterministic selected step as started before invoking an injected
 executor. Non-read-only authorization is consumed once by that durable first
 attempt; read-only execution continues to forbid authorization. Persist only
 stable IDs, allowlisted states, generations, timestamps, schema names, and
 digests for step/catalog/source/command/variables/result evidence. Never
 persist commands, variable values, output, addresses, inventory, environment,
 trust material, secrets, or protected paths. Accept only the exact
 per-playbook strict receipt and never infer success from exit zero. Any
 `started`, `failed`, `timed-out`, `interrupted`, `unreachable`, or
 `malformed-result` attempt requires manual recovery review and permanently
 forbids automatic retry; only strict success may advance to the next step.
 Keep the common v1 journal byte-for-byte at PLAN because it cannot represent
 these per-step states safely. The internal controlled-service executor adapter
 accepts only the resolved immutable step and exact typed current context,
 revalidates the matching operation lock, canonical rendered config/inventory/
 trust, readiness, catalog, packaged source and playbook hash, rebuilds the
 command-intent digest through the existing builder, and invokes only the
 existing service/runner. Accept only established strict per-playbook parser
 results; blocked/not-performed validation evidence is failure even after exit
 zero. Keep this handoff and adapter disconnected from the CLI and public
 operation registry until separately reviewed orchestration exists.
 The internal one-step coordinator accepts only canonical state-root/cluster
 identity, an operation UUID, the matching held operation lock, an exact sibling
 Ansible executable pair, and the controlled runner. It must load and revalidate
 canonical binding/context/journal/authorization/execution plus desired/
 observation/inventory/trust/rendered-runtime/source/catalog state. It must
 validate context, reconstruct request and allowlisted variables, and compare
 persisted context/plan/binding digests before probing either executable. It
 must then recompute machine readiness and the exact bound plan before durable
 intent, internally construct the controlled adapter, and call the existing
 handoff exactly once. Keep its
 `deploy-scylla-vms.ansible-operation-coordinator-report/v1` projection limited
 to counts/indices, bounded states, context/execution schemas and digests, and
 retry/recovery flags. The explicit context schema reconstructs bounded
 allowlisted read-only `check-jump-hosts`
 selector/depth/destination/check/timeout combinations. Refuse every other
 operation with
 `operation-context-unmodeled` before tool probing or `started` rather than
 accepting caller-supplied paths, plans, commands, variables, or environments.
 Do not loop, finalize, render, confirm, post-verify, or add public/CLI wiring in
 this coordinator.
 The internal `check-jump-hosts` orchestrator accepts only canonical
 state-root/cluster identity, the operation UUID, the matching already-held
 operation lock, an exact sibling Ansible executable pair, and the controlled
 runner. It must load the immutable context, prove the operation and effective
 class are exactly read-only, require unchanged `IN_PROGRESS/PLAN` history and
 absent authorization, and reconstruct the exact two-step
 `inventory-preflight` then `connectivity-check` plan before any tool probe.
 Drive only the next durable step by repeatedly calling the one-step coordinator,
 reloading and validating the execution companion after every call, with calls
 bounded by the immutable executable step count. An exact succeeded prefix may
 continue; complete succeeded execution may be observed idempotently. Any
 started, failed, timed-out, interrupted, unreachable, malformed, reordered,
 skipped, extra, or drifted state stops without retry. The strict
 `deploy-scylla-vms.ansible-check-jump-hosts-orchestration-report/v1` projection
 may report `steps-succeeded` with `semantic-evidence-ready` only when the exact
 durable semantic companion and both receipt bindings validate,
 `steps-succeeded` with `post-verification-pending` for legacy digest-only
 completion, or `execution-stopped` with finalization `not-reached`, plus
 bounded counts, states, schemas, and digests. The independently versioned
 `deploy-scylla-vms.ansible-operation-evidence/v1` companion belongs only at
 `<cluster-root>/operations/<operation-uuid>.ansible-operation-evidence.json`.
 Append each exact address-free parser projection after remote execution and
 strict parsing but before returning a successful seven-field receipt. Retain
 only inventory parity/status/counts/provenance or stable-ID host and requested
 role/port pair outcomes, bound to the exact request/plan/binding/context/
 catalog/source/readiness/observation/inventory/trust and step/result/command
 digests. Reject unknown or duplicate targets/pairs, addresses, host keys,
 routes, commands, variables, environment, raw output/events/module results,
 paths, credentials, secrets, reordered entries, and conflicting reuse. The
 handoff must re-read the exact projection digest before terminal success.
 Missing/mismatched evidence or a post-effect persistence failure requires
 manual recovery and permanently forbids automatic retry, including for this
 read-only operation. Never migrate legacy records from raw output, claim
 completed or healthy, advance the common v1 journal, or rewire the existing
 public no-write path in this layer.
 The separate internal `check-jump-hosts` post-verifier/finalizer accepts only
 canonical state-root/cluster identity, the operation UUID, and the matching
 already-held operation lock. It must load and revalidate binding/context/
 execution/evidence/journal plus current desired/observation/inventory/trust/
 readiness/source/catalog state itself. Require absent authorization, the exact
 reproduced two-step read-only plan, two terminal succeeded attempts with no
 recovery/retry ambiguity, and complete current receipt-bound semantic
 evidence. Reconstruct only the address-free public stable-ID and requested
 role/port result subset. Persist immutable
 `deploy-scylla-vms.ansible-operation-finalization/v1` first at
 `<cluster-root>/operations/<operation-uuid>.ansible-operation-finalization.json`,
 then append exact `VERIFY/completed` companion-digest evidence, then advance
 the unchanged common v1 journal to `SUCCEEDED/JOURNAL`. An exact companion-only
 or VERIFY prefix must resume idempotently without overwrite or duplicate
 events; exact terminal re-entry must write nothing. Any conflicting companion,
 stale provenance, duplicate/reordered event, or failed, unreachable, timed-out,
 interrupted, malformed, or started execution fails closed and remains manual
 recovery; never synthesize a clean FAILED verification from execution
 uncertainty. The strict
 `deploy-scylla-vms.ansible-operation-finalization-report/v1` projection may
 retain only allowlisted statuses/counts, stable IDs, role/port pairs, schemas,
 and digests. Keep addresses, hostnames, keys, routes, raw output, commands,
 variables, environment, protected paths, credentials, and secrets absent. The
 finalizer must not invoke a subprocess, collect confirmation, execute a step,
 mutate inventory/trust/readiness, add CLI wiring, or replace the public
 no-write workflow.
 The internal `check-jump-hosts` lifecycle coordinator composes only those
 reviewed checkpoint-preparation, deterministic orchestration, semantic-
 evidence, and finalization APIs. It accepts canonical state-root/cluster
 identity, one operation UUID, an optional typed request only while binding/
 context are not yet durably reconstructable, the matching already-held
 operation lock, and the controlled runner/executable pair. An existing exact
 `IN_PROGRESS/PLAN` common journal is a prerequisite; this layer never creates
 it. Determine the durable stage from canonical journal and companion records,
 call each component at most as needed, and bound execution by the immutable
 plan step count. Matching binding-only or binding-plus-context preparation,
 succeeded execution prefixes, semantic-evidence-ready completion,
 finalization-only/VERIFY prefixes, and terminal success may resume exactly.
 Terminal success must make no write or tool call. Wrong kind/class, forbidden
 authorization, missing journal/request, blocked plan, drift, legacy
 digest-only completion, or any started/failed/timed-out/interrupted/
 unreachable/malformed execution stops before later stages; uncertain
 execution remains manual-recovery/no-retry. Return only
 `deploy-scylla-vms.ansible-check-jump-hosts-lifecycle-report/v1` bounded stage
 states, journal status/phase, counts, schemas, and digests. Keep addresses,
 keys, routes, raw output, commands, variables, environments, protected paths,
 secrets, free-form input, rollback/deletion, confirmation, rendering, CLI
 wiring, and changes to the public no-write workflow absent. Every other
 operation remains unmodeled before writes or tool calls.
 The internal one-call `check-jump-hosts` composition accepts only canonical
 state-root/cluster identity, one operation UUID, the bounded typed request, the
 matching already-held operation-named `ClusterLock`, and the controlled
 runner/executable pair. The caller acquires the lock in the existing
 cluster-directory-then-lock-file order; composition must not acquire, nest, or
 release it. Call the existing initiation owner only for missing or exact
 untouched generation-1 state, then call the existing lifecycle under that
 same lock. For generation-2, companion, execution, evidence, finalization,
 VERIFY, and terminal prefixes, validate the caller request against the durable
 common-journal digest and enter lifecycle directly because initiation
 intentionally refuses advanced history. Do not duplicate any journal,
 preparation, orchestration, evidence, or finalization transition.
 Keep `deploy-scylla-vms.ansible-check-jump-hosts-operation-report/v1` limited
 to operation/classification, bounded initiation/lifecycle/stage states,
 status/phase, counts, retry/recovery flags, schemas, and digests. A blocked
 initiation must prevent lifecycle. Exact terminal re-entry must remain
 zero-write/zero-tool. Preserve typed application exceptions for the existing
 CLI error boundary; do not format protected component inputs or exceptions.
 Keep this composition internal and disconnected from the public write-free
 checker and all CLI paths.
  `storage-discover` retains only bounded provenance-bound device evidence.
 `storage-preflight` is the sixth available source: it is Scylla-only,
  return-only, and reports exact desired/manifest/discovery reconciliation with
  hashed public device identities and no device access or writes. Storage
 preparation is the seventh available source: `storage-prepare` is Scylla-only,
 serial-one, check-mode-refused, and requires fresh exact preflight plus
 operation/node/intent/device-set-bound authorization. It revalidates devices
 immediately before the first write, requires separate bound wipe consent,
 never executes `blocked`, does not rewrite `owned-noop`, and reports the first
 irreversible step and manual-recovery requirement. It has not been exercised
 on real devices and remains gated behind future operation orchestration.
 `storage-postcheck` is the eighth available source: it is Scylla-only,
 serial-one, read-only/check-mode-safe, and requires exact current discovery,
 preflight, preparation, desired, Terraform, inventory, trust, and lock
 provenance. It must fail closed on any device/RAID/XFS/UUID/fstab/mount/
 capacity/permission/marker conflict, return only hashed device identities and
 bounded blockers, and never repair, remount, write, or infer Scylla readiness
 from incomplete evidence.
 `storage-retire` is the twenty-fifth source-available production entry. It is
 destructive, Scylla-only, exact-one-target, serial-one, fatal, and
 check-mode-refused. Require current owned discovery, successful current
 postcheck/prepare evidence, observation/inventory/trust bindings, proven
 membership absence, and narrow authorization bound to the cluster, operation,
 stable ID, device-set digest, and `retain`/`delete`/`ephemeral` disposition.
 Refuse if Scylla is running, still a member, or devices are still claimed as
 active data. Never select by `/dev/nvme*` order. Revalidate hashed device
 identities immediately before the first irreversible step. Require separate
 bound wipe consent only when guest wipe occurs (`delete`); never wipe
 retained or ephemeral media, never execute `blocked`, and do not rewrite
 `owned-noop` prepare semantics. Unmount `/var/lib/scylla`, remove the UUID
 fstab entry, and deactivate exact RAID0 when present. Do not run Terraform,
 destroy VMs, or start/stop Scylla. Strict
 `deploy-scylla-vms.ansible-storage-retire/v1` results hash device identities
 and report mutation/recovery boundaries, provenance digests, explicit
 not-performed items, and redacted blockers.
 `service-converge` is the twenty-sixth source-available production entry. It
 is mutating, role-aware, exact-one-target, serial-one, fatal, and check-mode
 preview-only. Require Ubuntu 24.04, current `base-os` without reboot, and
 role-appropriate current install evidence. Allow only the PLAN-owned unit
 set: enable/start `systemd-timesyncd` when the scope is `base` or
 `jump-host`; keep `scylla-server` and `scylla-manager` masked/inactive and
 `scylla-manager-agent` / `scylla-node-exporter` disabled/inactive. Never
 unmask or start Scylla, Manager, exporters, or the monitoring stack.
 `restart_policy` never authorizes those starts. Succeed only when
 already-correct inactive/masked states match or timesyncd is converged.
 Strict `deploy-scylla-vms.ansible-service-converge/v1` results omit
 addresses and raw systemd output and report per-unit desired/observed
 enabled/active state, applied flags, provenance digests, explicit
 not-performed starts, and redacted blockers.
 `scylla-cluster-shutdown` is the twenty-seventh source-available production
 entry. It is destructive, Scylla-only, complete-set, serial-one, fatal, and
 check-mode-refused. Require current full-cluster `scylla-health`,
 observation/inventory/trust, and narrow authorization bound to cluster,
 operation, topology, and health digests. PLAN-cited 2026.2 administrator
 pages do not publish a reviewed drain-then-stop order, so inspect only
 argv-form `systemctl is-enabled`/`is-active` for `scylla-server` and never
 drain, stop, mask, start, decommission, wipe storage, or run Terraform.
 Manager quiesce is a separate prior playbook; while Manager remains
 unstarted, require explicit not-applicable/not-performed authorization
 rather than inventing `sctool suspend`. Strict
 `deploy-scylla-vms.ansible-scylla-cluster-shutdown/v1` results hash Host
 IDs, report per-node drain/stop/mask states, mutation/recovery boundaries,
 provenance digests, explicit not-performed items, and redacted blockers.
 `os-upgrade-preflight` is the twenty-eighth source-available production
 entry. It is read-only, role-aware, exact-one-target, serial-one, fatal, and
 check-mode-safe. Require exact current Ubuntu 24.04 on OCI `amd64`/guest
 `x86_64` or OCI/guest `aarch64`, current observation/inventory/trust and
 `base-os`, role-appropriate package/configuration/service/health evidence,
 route/availability evidence, and narrow operation/space-policy provenance.
 Scylla targets additionally require current storage, install/configure,
 complete cross-view health, and explicit replication/quorum/capacity/backup
 plus no-active-topology/shutdown/drain rolling evidence; unknown or failed
 gates block. Inspect only `/run/reboot-required`, argv-form `dpkg --audit`,
 fixed package-lock inodes through `/proc/locks`, Linux/architecture facts,
 and caller-policy-bound root/boot free space. PLAN defines no approved target
 OS transition beyond the current baseline, no exact kernel policy, and no
 read-only package-currency/repository proof, so same-release transitions are
 undefined, all other targets unsupported, and selected path always
 not-performed. Optional provider image facts are caller-supplied offline
 evidence only. Never run APT mutation, `do-release-upgrade`, reboot, service
 changes, desired-state mutation, OCI discovery, Terraform, or VM replacement.
 Strict `deploy-scylla-vms.ansible-os-upgrade-preflight/v1` results omit
 addresses/raw output and report transition classification, per-gate status,
 rolling eligibility, provenance digests, not-performed actions, and blockers.
 `os-upgrade-in-place` is the twenty-ninth source-available production entry.
 It is sensitive, role-aware, exact-one-target, serial-one, fatal, and
 check-mode-refused. Require a current execution-successful, explicitly
 rolling-eligible `os-upgrade-preflight/v1`; regenerate and compare exact
 observation/inventory/trust/`base-os` and role package/configuration/storage/
 health bindings; and require narrow authorization bound to operation, node,
 role, current/target OS, architecture, and all evidence digests. Refuse
 same-version requests as not upgrades, unsupported current/target OS,
 architecture mismatch, stale/failed/ineligible preflight, or authorization
 conflicts. PLAN approves no target transition, package sequence, role-safe
 shutdown, or reboot sequence. Therefore always return strict
 `deploy-scylla-vms.ansible-os-upgrade-in-place/v1` blocked evidence with
 `target-transition-unapproved`, plus `shutdown-sequence-unreviewed` for
 Scylla; mutation boundary `not-started`; package/source/service/reboot/kernel/
 configuration and automatic retry not-performed; and recovery-required false.
 Never run APT, modify sources or kernels, stop/start/unmask services, drain
 ScyllaDB, reboot, write config, mutate storage/Terraform/VM/cloud resources,
 or automatically retry. Source availability describes this reviewed refusal
 contract only and must never be presented as an implemented upgrade path.
 `os-reprovision-prepare` is the thirtieth source-available production entry.
 It is destructive preparation, role-aware, exact-one-target, serial-one,
 fatal, and check-mode-refused. Require current exact
 `os-upgrade-preflight/v1`, observation/inventory/trust/`base-os` and
 role-specific package/configuration/storage/health/lifecycle evidence,
 caller-supplied offline current/target provider-image facts, explicit storage
 disposition, and narrow authorization bound to cluster, operation, stable
 ID, current provider identity digest, old/new image OS/version/architecture,
 topology, and all evidence digests. Preserve stable logical identity and
 require the future provider identity to change; never claim caller facts prove
 OCI availability or capacity. Scylla must have completed reviewed membership
 removal evidence or remain explicitly blocked for `replace-node` delegation;
 generic Scylla reprovision is forbidden. Manager/monitoring/jump results must
 report unimplemented restore/re-registration/target-refresh/route/retrust
 requirements. PLAN approves no target transition or provider-replacement
 orchestration, so strict
 `deploy-scylla-vms.ansible-os-reprovision-prepare/v1` evidence always remains
 validation-only and blocked with mutation boundary `not-started`, recovery
 false, automatic retry false, and all provider/Terraform/VM/storage/package/
 service/membership/config/reboot actions not-performed. Never contact OCI, run
 Terraform, replace/destroy a VM, detach/delete/wipe storage, mutate packages,
 change desired state, stop/start services,
 drain/decommission/removenode, edit configuration, reboot, restore,
 re-register, refresh targets, or retrust a host. Source availability means
 only that this executable refusal contract is packaged.
 `os-upgrade-postcheck` is the thirty-first source-available
 production entry. It is read-only, role-aware, exact-one-target, serial-one,
 fatal, and check-mode-safe. Require an exact source-operation result and
 matching authorization from `os-upgrade-in-place/v1` or
 `os-reprovision-prepare/v1`, plus current observation/inventory/trust,
 `base-os`, package, configuration, storage, route, service, and role-health
 evidence. Bind cluster, operation, stable/provider identity, exact previous/
 target/current OS version and architecture, source mode/schema/result digest,
 generations, and all provenance digests. Current source results are
 validation-only (`mutation_boundary=not-started`, `applied=false`, blocked or
 failed, and mutation actions not-performed); never treat them as upgrades and
 always retain `source-upgrade-not-performed`. Same-version, unsupported, and
 PLAN-unapproved transitions cannot verify. Bounded host reads may inspect only
 `/etc/os-release`, architecture, kernel release, `/run/reboot-required`,
 argv-form `dpkg --audit`, exact allowlisted package versions, and fixed
 allowlisted service state. Scylla requires complete current topology/schema/
 streaming/storage-health evidence and must never infer health from process
 state. Strict `deploy-scylla-vms.ansible-os-upgrade-postcheck/v1` results omit
 addresses, provider/raw command/package output, device paths, secrets, and
 environment; report per-gate and verification coverage, provenance, and
 mutation/remediation false. Never mutate APT/packages, reboot, change services
 or configuration/storage/trust, contact OCI/Terraform, mutate Scylla, or
 remediate. Source availability means only that this truthful verifier/refusal
 is packaged; no supported source currently proves a completed OS change.
 `base-os` supports exactly Ubuntu 24.04 on OCI `amd64`/guest `x86_64` and
  OCI/guest `aarch64`; it must validate exact configured image evidence against
  gathered facts, apply only generic APT prerequisites and
  `systemd-timesyncd`, report reboot requirement without rebooting, and retain
  no raw module output. New desired state must refuse Oracle Linux and every
  other OS without silently migrating persisted desired records.
 `scylla-install` is packaged, hash-checked, and source-available with a
 vendored public signing key authenticated against the official repository's
 signed full-fingerprint evidence and immutable official key-ID references. It
 validates the artifact digest, primary/subkey fingerprints, UID, and
 revocation-packet absence before use. It
  requires successful current
  base-OS and storage-postcheck evidence, exact Ubuntu/architecture and complete
  provenance bindings, and an exact ScyllaDB 2026.2 package version. It owns the
  signed APT repository and package installation, masks/stops
  `scylla-server` before package work, prevents maintainer-script startup, and
  leaves the service masked/inactive. It must not configure Scylla, topology,
  storage, tuning, Manager, kernel policy, or reboot. The upstream role is
  pinned immutably as provenance but is not invoked by installation while its
  Ubuntu path uses broader unsafe behavior.
  `scylla-configure` is the tenth source-available production entry. It uses
  wrapper-owned templates because the pinned upstream role cannot be safely
  constrained to configuration-only behavior. Keep its exact ScyllaDB 2026.2
  allowlist, fixed `/var/lib/scylla` subdirectories, normalized immutable
  cluster/datacenter/rack identity, RFC 1918 private-address checks,
  deterministic bounded persisted stable-ID seed policy, exact prerequisite
  digests, root-owned `0644` files, and masked/inactive service gates. It may
  configure only `scylla.yaml` and `cassandra-rackdc.properties`; it must not
  install packages, modify storage/tuning/firewall/SSH/Manager, start or
  bootstrap Scylla, claim health, or run Scylla. Check mode remains
  non-predictive, and strict results must report
  `runtime_validation_performed=false` without raw config or addresses.
 `scylla-bootstrap` is the eleventh source-available production entry. It is
 Scylla-only, exact-one-target, serial-one, fatal, and check-mode-refused. Its
 only modes are explicit `initial-seed` for a reviewed empty new cluster and
 `join-existing` for an exact add/scale intent backed by healthy surviving
 members/seeds, target absence, and capacity/topology/schema gates. Bind
 operation/node/spec/observation/inventory/trust/storage/install/configuration/
 topology/seed evidence, revalidate immediately before systemd unmask/start,
 and use bounded CQL plus argv-form `nodetool` membership/streaming/schema
 checks. Results must use strict
 `deploy-scylla-vms.ansible-scylla-bootstrap/v1`, hash ring/Host-ID evidence,
 omit addresses/raw output, and identify whether membership may have changed.
 Never automatically retry or destroy after failure; remask only when the node
 is proven never joined, otherwise preserve it for reviewed recovery. Dead-node
 removal and replacement remain separate slices.
 `scylla-health` is the twelfth source-available production entry. It is
 Scylla-only, read-only, check-mode-safe, serial-five, and normally queries the
 exact complete Scylla stable-ID set so Python can establish each local Host ID
 and compare every normalized ring view. A one-coordinator limit is allowed
 only with a complete unique prior stable-ID/Host-ID map and exact current
 provenance. It uses fixed argv-form `nodetool info`, `status`,
 `describecluster`, and `netstats` plus read-only service and local CQL/API
 reachability checks; no shell or mutating command is permitted. Strict
 `deploy-scylla-vms.ansible-scylla-health/v1` results must omit addresses and
 raw output, bind observation/inventory/trust/storage digests, and fail closed
 on missing/extra/duplicate/transitional/down members, topology or identity
 conflicts, inconsistent views, schema disagreement, streaming, service/API/
 CQL failure, or storage unreadiness. Unauthenticated replication, quorum, and
 Manager backup policy checks remain explicit unknown/not-performed blockers
 for stronger operation classes.
 `scylla-remove-live` is the thirteenth source-available production entry. It
 is destructive, Scylla-only, exact-one-target, serial-one, fatal, and
 check-mode-refused. Require fresh complete `scylla-health/v1`, an exact Up
 Normal target, and independently validated passed replication, quorum,
 post-removal capacity, and backup-policy evidence; unknown is never a pass.
 Bind exact desired removal intent and narrow destructive authorization to the
 cluster, operation, stable ID, Host ID, provider ID, datacenter/rack, current
 observation/inventory/trust/config/storage/health evidence, and intended
 post-removal topology. Revalidate target identity from the target and a healthy
 survivor immediately before argv-form `nodetool decommission`, then prove
 target absence, survivor Up Normal state, schema agreement, idle streaming,
 and exact topology from a survivor. A started command requires journaled
 recovery and must never be retried blindly. This slice must not stop/destroy
 infrastructure, wipe storage, edit desired state, or run Terraform. Dead-node
 removal is a separate slice.
 `scylla-remove-dead` is the fourteenth source-available production entry. It
 is destructive, Scylla-only, coordinator-only, exact-one-target, serial-one,
 fatal, and check-mode-refused; its stable-ID limit is the explicitly selected
 healthy survivor and must never be the dead target. Require independent
 SSH/service/provider evidence that the exact stable/Host/provider identity is
 unchanged, unreachable, and still present as Down Normal in consistent
 survivor ring views; refuse ambiguity, target reachability/absence, or another
 active removal/replacement. Bind fresh survivor health/schema/streaming,
 replication, quorum, capacity, backup policy, intended post-topology, current
 observation/inventory/trust, and narrow destructive authorization. Revalidate
 the required survivor quorum immediately before exact argv-form
 `nodetool removenode <host-id>`, never invoke force completion, and poll only
 supported status/read commands until exact absence, Up Normal survivors,
 schema agreement, idle streaming, and post-topology are proven. Started,
 failed, interrupted, or timed-out commands require journaled recovery review
 and must not be retried blindly. This slice must not contact the dead target,
 mutate desired/provider/storage/Terraform state, or remove infrastructure.
 `scylla-replace-dead` is the fifteenth source-available production entry. It is
 destructive, Scylla-only, exact-one-new-target, serial-one, fatal, and
 check-mode-refused. Require the old exact Host ID to remain DN in consistent
 healthy quorum survivor views, independent old-target unreachability, no prior
 `removenode`, no active topology operation, a distinct new provider identity,
 explicitly reviewed stable-ID mapping, empty freshly prepared storage, exact
 ScyllaDB 2026.2 patch/config/cluster/DC/rack/seeds, current observation/
 inventory/trust, all-passed replication/quorum/capacity/backup evidence, and
 narrow authorization bound to every identity and evidence digest. Immediately
 revalidate survivors and replacement state, forbid `replace_address*`, and
 atomically add only `replace_node_first_boot: <dead-host-id>` to validated
 `scylla.yaml` while the service is masked/inactive. Systemd unmask/start is the
 irreversible boundary. Poll bounded survivor `gossipinfo`, `status`,
 `describecluster`, and `netstats` until one new Host ID is UN, the old Host ID
 is absent, exact topology agrees, schema agrees, and streaming is idle; never
 identify membership by IP. Retain the one-time key after success. Never run
 `removenode`, force, repair, destroy, wipe, or blindly restart in this slice.
 Strict results bind hashed old/new Host and provider identities, pre/post
 digests, mutation/recovery boundaries, and repair/RBNO status. Repair remains
 required and blocks finalization unless strict RBNO-enabled-and-complete
 evidence proves it unnecessary; repair and post-scale cleanup remain separate
 slices.
 `scylla-repair` is the sixteenth source-available production entry. It is
 sensitive, Scylla-only, exact-one-target, serial-one, fatal, and
 check-mode-refused. Its only reasons are mandatory post-replacement repair and
 operator-reviewed post-bootstrap repair. Require fresh complete cross-view UN
 health, exact Host ID/DC/rack/2026.2 version, schema agreement, idle streaming,
 current observation/inventory/trust/config/storage and source-result digests,
 passed capacity/quorum evidence, no competing operation, and narrow
 target/reason/evidence-bound authorization. Complete enabled RBNO replacement
 evidence may produce a strict no-op; never infer RBNO from version and never
 apply the skip to bootstrap. Immediately revalidate with fixed read commands,
 then run only foreground argv-form `nodetool repair` with a bounded timeout.
 Require post-health and no pending repair/compaction work; exit zero alone is
 insufficient. Direct completion is operational rather than cryptographic and
 remains explicit-review-required. Strict
 `deploy-scylla-vms.ansible-scylla-repair/v1` results omit raw output and
 addresses and preserve command-start/completion, recovery, and blockers.
 Timeout/interruption must never trigger automatic retry. Manager-scheduled
 repair remains a separate later slice.
 `scylla-cleanup` is the seventeenth source-available production entry. It is
 sensitive, Scylla-only, exact-one-target, serial-one, fatal, and
 check-mode-refused. Require a completed healthy add-node/scale-out result and
 target only the 2026.2 eligible set: pre-existing survivors plus earlier
 joined nodes for multi-node scale-out, never the last joined node. Require
 fresh complete cross-view UN health, exact post-expansion topology, schema
 agreement, idle streaming, sufficient disk/compaction headroom, current
 observation/inventory/trust/config/storage bindings, any required completed
 repair/RBNO evidence, no competing work, and narrow operation/target/evidence
 authorization. Immediately revalidate with fixed read commands, then run only
 foreground argv-form `nodetool cleanup` with a bounded timeout and poll
 supported health/compaction commands to completion. Strict
 `deploy-scylla-vms.ansible-scylla-cleanup/v1` results omit raw output and
 addresses and retain hashed Host ID, source/repair and health digests,
 command/pending-work boundaries, recovery, and blockers. Failure, timeout, or
 interruption must stop the serial sequence, require journal review, and never
 trigger automatic retry.
 `jump-host-configure` is the eighteenth source-available production entry. It
 is mutating, jump-only, exact-one-target, serial-one, fatal, and check-mode
 preview-only. Require current Ubuntu `base-os` evidence without reboot, complete
 trust, valid inventory-derived ProxyJump routes, and narrow
 operation/node/observation/inventory/trust/base-os/config authorization. Install
 only `/etc/ssh/sshd_config.d/00-deploy-scylla-vms.conf` with password/KbdInteractive/
 ChallengeResponse `no`, `PermitRootLogin no`, public-key-only authentication,
 `AllowTcpForwarding local`, `PermitOpen` from exact RFC 1918 private host:22
 routes or `none`, inventory `AllowUsers`, and no agent/X11/tunnel/stream-local
 forwarding or host-key bypass. Validate with argv-form `ssh-keygen -l` and
 `sshd -t`, restore the previous valid drop-in on failure, and reload Ubuntu
 `ssh` only after a successful change. Strict
 `deploy-scylla-vms.ansible-jump-host-configure/v1` results omit addresses, raw
 sshd output, and configuration text. Do not create network or compute
 resources. Live use remains gated by deploy/host-scope orchestration.
 `manager-agent` is the nineteenth source-available production entry. It is
 mutating, Scylla-only, serial-one, fatal, and check-mode preview-only. Require
 current Ubuntu `base-os` evidence without reboot, successful current
 `scylla-install` evidence, exact Ubuntu 24.04/architecture, and complete
 observation/inventory/trust provenance. Install only the exact Manager 3.12
 `scylla-manager-agent` package from the official Ubuntu Manager 3.12 repository
 signed by the already-authenticated 2026 key. Prevent maintainer-script
 startup, leave the agent disabled/inactive, and do not write `auth_token`, run
 `scyllamgr_agent_setup`, start Scylla, or claim server reachability. Strict
 `deploy-scylla-vms.ansible-manager-agent/v1` results omit addresses and raw
 package output and report configuration/token/helper-slice/reachability as
 false or `not-performed`.
 `manager-server` is the twentieth source-available production entry. It is
 mutating, manager-only, exact-one-target, serial-one, fatal, and check-mode
 preview-only. Require current Ubuntu `base-os` evidence without reboot, exact
 Ubuntu 24.04/architecture, and complete observation/inventory/trust
 provenance. Install only the exact Manager 3.12 `scylla-manager-server` and
 `scylla-manager-client` packages from the official Ubuntu Manager 3.12
 repository signed by the already-authenticated 2026 key. Prevent
 maintainer-script startup, leave `scylla-manager` masked/inactive, and do not
 configure a local or remote Scylla backend, write `scylla-manager.yaml`, run
 `scyllamgr_setup`, persist an environment token, register a cluster, create
 tasks, or start Manager. Strict `deploy-scylla-vms.ansible-manager-server/v1`
 results omit addresses and raw package output and report
 `backend_configured`, `registration_performed`, `setup_performed`, and
 `service_started` as false.
 `manager-tasks` is the twenty-fourth source-available production entry. It
 is sensitive, manager-only, exact-one-target, serial-one, fatal, and
 check-mode preview-only. Require current Ubuntu `base-os` evidence without
 reboot, current `manager-server` evidence that remains masked/inactive and
 unregistered, exact Ubuntu 24.04/architecture, and complete
 observation/inventory/trust provenance. Validate only PLAN
 `inspect`/`quiesce`/`resume`/`validate` actions for official backup/repair
 kinds. Do not start or unmask Manager, write tokens or
 `scylla-manager.yaml`, register a cluster, invoke `sctool`, or start Scylla.
 Official Manager 3.12 task APIs require a live registered API; this slice
 remains validation-only. Strict
 `deploy-scylla-vms.ansible-manager-tasks/v1` results omit addresses and raw
 command output and report `applied=false` with inspect/quiesce/resume/
 validate/backup/repair/sctool as not-performed and exact inactive,
 unregistered, and backend blockers.
 `monitoring-agent` is the twenty-first source-available production entry. It
 is mutating, Scylla-only, serial-one, fatal, and check-mode preview-only.
 Require current Ubuntu `base-os` evidence without reboot, successful current
 `scylla-install` evidence, exact Ubuntu 24.04/architecture, and complete
 observation/inventory/trust provenance. Install only the exact ScyllaDB 2026.2
 `scylla-node-exporter` package from the official Ubuntu Scylla 2026.2
 repository signed by the already-authenticated 2026 key. Prevent
 maintainer-script startup, leave `scylla-node-exporter` disabled/inactive, and
 do not bind port 9100, write exporter configuration, install process-exporter
 or the monitoring stack, generate target files, register Manager, or start
 Scylla. Strict `deploy-scylla-vms.ansible-monitoring-agent/v1` results omit
 addresses and raw package output and report listen policy as `not-started`
 with stack/targets/process-exporter/registration/startup as false.
 `monitoring-stack` is the twenty-second source-available production entry. It
 is mutating, monitoring-only, exact-one-target, serial-one, fatal, and
 check-mode preview-only. Require current Ubuntu `base-os` evidence without
 reboot, exact Ubuntu 24.04/architecture, and complete observation/inventory/
 trust provenance. Install only the digest-pinned official Scylla Monitoring
 4.16.0 archive whose tagged `versions.sh` pins Prometheus v3.14.0, Grafana
 13.2.0, Alertmanager v0.34.0, Loki 3.7.7, and Promtail 3.6.11 and lists
 ScyllaDB 2026.2. Do not install Docker, pull unsigned images, start
 containers, generate Compose/auth/targets, bind Grafana 3000 / Prometheus
 9090 / Alertmanager 9093, register Manager, or start Scylla. Strict
 `deploy-scylla-vms.ansible-monitoring-stack/v1` results omit addresses and
 raw archive output and report listen policy as `not-started` with
 targets/auth/public-bind/Compose/containers/Manager/Scylla/secrets as false.
 `monitoring-targets` is the twenty-third source-available production entry. It
 is mutating, monitoring-only, exact-one-target, serial-one, fatal, and
 check-mode preview-only. Require current Ubuntu `base-os` evidence without
 reboot, current `monitoring-stack` 4.16.0 evidence, exact Ubuntu
 24.04/architecture, and complete observation/inventory/trust provenance.
 Generate only official Scylla Monitoring 4.16.0 Prometheus target files under
 `/opt/scylla-monitoring/4.16.0/prometheus/` from RFC 1918 inventory identities:
 `scylla_servers.yml` with cluster/dc labels and no default ports, required
 `scylla_manager_servers.yml` as Manager `host:5090`, and official reuse copies
 `node_exporter_servers.yml` and `scylla_manager_agents.yml`. Do not start
 Docker, Prometheus, Grafana, Alertmanager, or node_exporter, bind UI ports,
 install the stack or agents, register Manager, or start Scylla. Strict
 `deploy-scylla-vms.ansible-monitoring-targets/v1` results omit addresses and
 file contents and report listen policy as `not-started` with scrape-readiness
 `not-performed` and scrape/exporter/stack/container/auth/public-bind/Compose/
 Manager/Scylla/secrets as false.
- Keep inventories generated deterministically from validated Terraform JSON
  outputs. Generated inventories are runtime artifacts and must not be committed.
- The local inventory contract is `deploy-scylla-vms.inventory/v1`, serialized
  as deterministic JSON-compatible static inventory at
  `<cluster-root>/ansible/inventory.yml`. Keep stable logical host keys, exact
  source-manifest generation/digest binding, collision-checked role/zone/
  datacenter/rack groups, structured routing metadata, mandatory host-key
  checking, explicit write approval, and owner-only atomic persistence.
- Keep the persisted static inventory shape accepted by Ansible distinct from
  the normalized `ansible-inventory --list` evidence shape; validate exact
  parity rather than writing machine-output JSON back as inventory input.
- Refresh and validate inventory before sensitive or destructive actions and
  whenever Terraform output changes. Stop on identity, membership, host-key, or
  topology conflicts.
- Persist independently versioned SSH trust only at
  `<cluster-root>/ansible/trust.json`, with deterministic derived
  `known_hosts` and `ssh_config` files. Bind every confirmed key to current
  observation/inventory generations and digests, stable logical/provider IDs,
  canonical endpoint, port, and jump route. Only Ed25519 and NIST P-256 ECDSA
  host keys are currently approved; a changed key or identity requires a
  separately reviewed replacement workflow.
- Direct `ssh-keyscan` creates candidates only. First trust requires explicit
  operator confirmation or an independently supplied matching SHA-256
  fingerprint. Never use TOFU, generic `--yes`, an interpolated `ProxyCommand`,
  or disabled checking. The direct portable boundary still refuses private-host
  scans through jumps. The reviewed internal `routed-keyscan` support source may
  collect candidates only after the assigned jump is currently trusted and
  exact machine inventory/routes are valid. Accept stable-ID selection only;
  derive bounded RFC 1918 endpoints and fixed port 22 from canonical inventory.
  Execute exactly one jump, serial one, through generated strict host-key-
  checking configuration. On the jump invoke only canonical
  `/usr/bin/ssh-keyscan` with argv/no shell, controlled locale, fixed Ed25519
  and NIST P-256 ECDSA types, and bounded timeout/output. Keep endpoint payloads
  `no_log`, force this one command's Ansible log path to `/dev/null`, and return
  only strict address-free candidate evidence. Revalidate observation/
  inventory/trust/readiness, stable/provider identities, routes, source, and
  policy before accepting the in-memory collection. Never persist or promote
  these candidates, rewrite trust/SSH derivatives, journal the collection, or
  treat collection as host health or private connectivity. Existing or changed
  trust requires the separate replacement workflow.
- Production Ansible execution requires a current machine-validated readiness
  report proving exact inventory hostvars/groups, deterministic jump routing,
  complete trust, and observation/inventory/trust bindings. Local `show` may
  report missing machine validation or trust truthfully without external calls.
- Controller-only `inventory-preflight` requires fresh source and exact machine
  inventory evidence but does not require host trust or make a host connection.
  `connectivity-check` requires complete trust and valid routes, uses only
  explicitly validated stable-ID limits, and preserves redacted per-host
  success/failure/unreachable evidence.
- The public `check-jump-hosts` workflow is read-only under `ClusterReadLock`.
  It requires complete current local observation/inventory/trust/route evidence,
  runs preflight before connectivity, and limits live checks to selected jump
  stable IDs. Destination TCP checks accept only the documented role/port
  allowlist, derive RFC 1918 targets from assigned typed inventory routes, use
  bounded `ansible.builtin.wait_for` from the jump, and emit address-free pair
  evidence. Keep private-target SSH and arbitrary destination probing
  unavailable; do not add journal or canonical-state writes to this operation.
- `evidence-collect` requires fresh readiness and exact stable-ID limits. Keep
  its collection bounded to the reviewed host/system/capacity/approved-mount/
  redacted-device/allowlisted-service/role-applicable-health projection. Never
  add environment, process-command, credential, metadata, arbitrary-file, raw
  inventory, or unrestricted-log collection. Parse only strict
  `deploy-scylla-vms.ansible-host-evidence/v1`; do not persist raw output.
  Collection is write-free. Optional
  `deploy-scylla-vms.diagnostics-evidence/v1` persistence belongs only at
  `<cluster-root>/logs/evidence.json` and requires explicit approval, a matching
  lock, current observation/inventory/trust bindings, atomic owner-only writes,
  and generation/digest guards.
- Roles and playbooks must be idempotent, support safe reruns, and use deliberate
  handlers, conditions, check-mode behavior, serial limits, and health gates.
- Pin collections and external roles. Validate ScyllaDB role behavior against
  current official docs and upstream source; GitHub wiki guidance can be stale.
- When implementation introduces or changes a workaround for a verified
  upstream ScyllaDB Ansible role gap, update `UPSTREAM_TODO.md` in the same
  change. Do not classify unrelated project scope as an upstream gap, and close
  or adopt an entry only with verified immutable upstream evidence.
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
- Public report schemas must be independently versioned and built through
  explicit allowlist projections. Never expose persistence models directly;
  omit protected paths/identifiers and distinguish `fresh`, `stale`, `unknown`,
  `unavailable`, and `not-performed` evidence without inferring health or
  no-drift.
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

- Use the established project environment and checks:
  `python -m pip install --editable ".[dev]"`, `ruff format --check .`,
  `ruff check .`, `mypy`, and `pytest`. Ruff, mypy, and pytest are configured in
  `pyproject.toml` and run in CI.
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
