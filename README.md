# deploy-scylla-vms

`deploy-scylla-vms` is an early Python command-line foundation for provisioning
and operating ScyllaDB clusters on virtual machines.

**Current status:** the package, complete per-operation CLI contract, strict
non-secret TOML defaults loader, immutable desired-cluster model, and secure
local state primitives exist. `ClusterSpec` covers resolved OCI placement,
topology, stable initial logical IDs, explicit per-role image filters,
role placement/shapes, explicit managed-network CIDRs/private networking/
SSH references, and role-specific storage policy with deterministic schema and
digest handling. The versioned cluster record persists that complete desired
specification behind generation/digest guards. `show` now renders validated
canonical local state. A controlled external-process runner, strict Terraform
CLI version probe, fully anchored Terraform command builders, and
versioned output/host/storage JSON parsers are available as internal APIs. An
internal lock-bound saved-plan checkpoint now binds exact plan bytes/JSON,
toolchain, desired/tfvars/source generations and digests, the initial operation
journal, and the canonical local-state serial plus hashed lineage/snapshot. It
persists only redacted action/drift classes, counts, and scope digests at
`<cluster-root>/terraform/plans/<operation-uuid>.terraform-plan.json`; that
checkpoint layer leaves apply authorization uncollected and constructs no
apply/destroy command. A narrow
internal deploy-only composition API now revalidates that immutable checkpoint
and current canonical bindings under the matching held lock, then appends its
exact digest as the sole validated PLAN event in the existing common journal.
Checkpoint-first recovery and exact idempotent reuse are supported; status
remains `in-progress`/`plan`, execution remains unavailable, and no public
deploy path is enabled. A controlled internal deploy PLAN orchestrator now
validates the exact initial journal and canonical desired/tfvars/source/backend/
state/toolchain bindings, creates only
`<operation-uuid>.tfplan.staging`, runs strict `terraform show -json` against
that exact artifact, atomically promotes it to `<operation-uuid>.tfplan`,
persists the checkpoint, and invokes the existing composer. Detailed exit 0/2
semantics, saved-plan/checkpoint recovery, and zero-tool terminal re-entry are
fake-runner tested. Ambiguous staging, changed inputs, or conflicting artifacts
fail closed without automatic replanning; that planning layer never applies.
An internal `authorize_deploy_apply` API now revalidates that exact composed
PLAN checkpoint and persists immutable owner-only
`deploy-scylla-vms.terraform-apply-authorization/v1` at
`<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-authorization.json`
only when apply is required. The effective mutating/destructive class comes from
the reviewed plan: no-change creates no authorization; create/update accepts
ordinary interactive or `--yes` approval; replacement/deletion additionally
requires a normalized `--allow-destructive` fact and exact address-free
count/scope proof. Benign refresh drift requires separate interactive review,
conflicting drift is refused, and absent initial state permits only drift-free
creation. A separate internal `safeguard_deploy_apply_state` API now requires
that exact unconsumed authorization and persists immutable
`deploy-scylla-vms.terraform-state-safeguard/v1` before any future apply. For
existing canonical local state it writes an operation-scoped owner-only exact
backup at `<cluster-root>/terraform/backups/<operation-uuid>.terraform.tfstate`;
for a verified absent initial state it records absence without creating a fake
state or backup. Validation precedes backup, which precedes the safeguard
record; an exact backup-only prefix is recoverable, while changed bindings or
conflicting artifacts fail closed. The common journal remains unchanged at
PLAN and authorization remains unconsumed until the separate internal
`execute_deploy_apply` owner runs. That API persists owner-only
`deploy-scylla-vms.terraform-apply-execution/v1` at
`<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-execution.json`,
advances the common journal only to nonterminal `IN_PROGRESS/EXECUTE`, durably
records `started` to consume authorization, and then invokes exactly
`terraform apply -input=false -no-color -lock=true -lock-timeout=30s
<canonical-saved-plan>`. Exit zero is retained only as
`process-succeeded-verification-pending`; every started uncertain outcome is
manual-recovery/no-retry, and exact re-entry never invokes Terraform again.
The separate internal `verify_deploy_apply` continuation accepts only that
exact process-success state, verifies canonical post-apply state lineage,
serial, digest, ownership, mode, and descriptor/path stability, advances the
common journal only to nonterminal `IN_PROGRESS/VERIFY` with the exact prior
observation-or-absence baseline, and invokes only the anchored
`terraform output -json` command. It strictly validates all host,
image, network, topology, and storage output bindings, reconciles the result
against current desired state, writes only validated
`deploy-scylla-vms.observed/v1`, and then persists immutable
`deploy-scylla-vms.terraform-apply-verification/v1` at
`<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-verification.json`.
An exact observation-only partial prefix recovers without another output call,
and exact completed re-entry is zero-process. This proves only infrastructure
observation reconciliation. A separate internal `generate_deploy_inventory`
continuation now revalidates that exact successful verifier, execution/plan,
`IN_PROGRESS/VERIFY` journal, and current desired/tfvars/source/observation
bindings, then deterministically writes or reuses only the canonical owner-only
`deploy-scylla-vms.inventory/v1`. It persists immutable
`deploy-scylla-vms.terraform-apply-inventory/v1` at
`<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-inventory.json`
with address-free counts and topology/group/route digests. An exact
inventory-only prefix is recoverable; current/missing/stale trust is classified
without rewriting trust or rendering SSH/controller files. The separate
internal `establish_deploy_ssh_trust` continuation consumes only existing typed
direct/routed candidates and normalized per-key explicit-confirmation or
independent-fingerprint proofs. It establishes direct jump trust first, reports
private trust pending, then accepts routed private candidates only while the
exact jump trust remains current. It writes guarded `trust.json`,
`known_hosts`, and `ssh_config`, and, only after every inventory host is current,
persists immutable `deploy-scylla-vms.terraform-apply-trust/v1` at
`<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-trust.json`.
Exact stale trust requires explicit per-key revalidation, changed identities or
keys fail closed, and trust-only partial persistence can recover without host
contact. Machine validation/readiness, Ansible, deploy finalization, and public
deploy wiring remain pending.
All execution tests use injected fake runners. No CLI invokes these APIs.
Strict local Terraform-observation and generated-inventory records, deterministic
desired/observed reconciliation, and a local inventory refresh service now
complete the read-only reporting pipeline. An offline OCI adapter, strict
provider-input/tfvars contract, public-key validator, approved-source bundle
model, and tamper-safe source stager are internal APIs. The packaged,
hash-manifested, planning-ready `oci-root/v3` Terraform source provides exact v2
input types, OCI provider 9.1.x locking, deterministic platform-image lookup,
managed or existing networking, role NSGs, stable-ID compute, Block Volume and
local-NVMe branches, and strict host/storage/image/network outputs.
An internal Ansible execution foundation now provides strict
ansible-core version probes, controlled inventory/playbook command construction,
owner-only ephemeral non-secret extra-vars files, an integrity-checked
state-anchored configuration, and a complete 33-entry playbook/operation
registry. Exactly `inventory-preflight`, `connectivity-check`,
`routed-keyscan`, `evidence-collect`, `jump-host-configure`, `base-os`,
`deploy-reboot`,
`storage-discover`,
`storage-preflight`,
`storage-prepare`, `storage-postcheck`, `storage-retire`, `service-converge`,
`scylla-cluster-shutdown`, `os-upgrade-preflight`,
`os-upgrade-in-place`, `os-reprovision-prepare`, `os-upgrade-postcheck`,
`scylla-install`,
`scylla-configure`, `scylla-bootstrap`, `scylla-health`,
`scylla-remove-live`, `scylla-remove-dead`, `scylla-replace-dead`,
`scylla-repair`, and `scylla-cleanup` have packaged, hash-checked production
sources, with `jump-host-configure` as the eighteenth source-available entry,
`manager-agent` as the nineteenth, `manager-server` as the twentieth,
`manager-tasks` as the twenty-fourth, `monitoring-agent` as the twenty-first,
`monitoring-stack` as the twenty-second, `monitoring-targets` as the
twenty-third, `storage-retire` as the twenty-fifth, `service-converge`
as the twenty-sixth, and `scylla-cluster-shutdown` as the
twenty-seventh, `os-upgrade-preflight` as the twenty-eighth, and
`os-upgrade-in-place` as the twenty-ninth, and
`os-reprovision-prepare` as the thirtieth, `os-upgrade-postcheck` as the
thirty-first production entry, the routed candidate scanner as the
thirty-second support entry, and the deployment-only reboot source as the
thirty-third support entry. The Manager-local backend preflight, package
install, dedicated-storage discovery, and dedicated-storage preflight sources
complete the current 37-entry catalog. All 37 entries now have reviewed
packaged sources.
Preflight validates static inventory provenance, stable identities, topology,
and explicit operation membership without connecting to hosts. Connectivity
uses bounded, check-mode-safe Ansible ping checks only after current inventory,
trust, and typed routing gates pass, and returns redacted per-host partial
failure evidence. It also performs bounded, allowlisted private TCP probes from
selected jumps with redacted per-pair evidence. Strict internal SSH trust adds
candidate-only direct discovery,
explicit fingerprint/confirmation promotion, immutable observation/inventory-
bound trust persistence, deterministic `known_hosts`/SSH configuration, stable
multi-jump routing validation, exact `ansible-inventory` machine-output
validation, and operation-class readiness gates. Local `show` projects only
fingerprints and readiness summaries. An internal lock-bound offline
operation-plan resolver combines the public operation registry with conditional
catalog steps, command-policy validation, explicit stable-ID limits, allowlisted
variable schemas, readiness blockers, redacted plan digests, and PLAN-phase
checkpoint evidence. It creates no runtime file, invokes no process, persists no
journal, and keeps every unimplemented public workflow explicitly blocked. A
separate internal matching-lock API can now persist an immutable
`deploy-scylla-vms.ansible-operation-binding/v1` request/plan checkpoint beside
the common journal and validate an unchanged PLAN-phase checkpoint for offline
resume. It binds request, plan, target, catalog, packaged-source, readiness,
observation, inventory, trust, and journal digests without retaining raw
variables, commands, paths, addresses, keys, or secret values. After that
binding exists, a separate matching-lock API can persist immutable
`deploy-scylla-vms.ansible-operation-context/v1`. Its sole modeled values schema
contains bounded native `check-jump-hosts` stable-ID selectors, destination/depth
enums, role/port checks, and connection/aggregate timeouts. It binds the exact
request, plan, binding, classifications, and selected stable IDs, but re-derives
addresses and runtime probe variables from current canonical inventory. For an
exact unblocked non-read-only plan, another matching-lock API can persist immutable
`deploy-scylla-vms.ansible-operation-authorization/v1` at the same operation
scope. It applies the existing class and operation-specific confirmation rules
and stores only separated normalized proof enums and digests. Read-only work
creates no authorization; ordinary `--yes` never supplies destructive scope,
wipe, recreation, reprovision, or monitoring-restart consent. The common
journal remains at PLAN and resume validation v2 requires exact unchanged
authorization where applicable while refusing confirm-or-later, failed,
interrupted, completed, destructive-boundary, stale, drifted, replayed,
cross-scope, or ambiguous histories. A narrow internal checkpoint-preparation
coordinator now loads the existing canonical PLAN journal and current local
state, derives the modeled request context, resolves the exact plan, and
sequences those existing stores as binding, context, then class-appropriate
authorization. It reuses byte-identical records and can continue a matching
binding-only or binding-plus-context prefix before execution. Any mismatch,
unsafe history/path, execution companion, or changed evidence/source/catalog
fails closed without overwrite, deletion, rollback, or journal advancement.
Its independently versioned redacted report exposes only stage states,
schemas/digests, safe operation/stable IDs, blockers, and pre-execution resume
truth. Only `check-jump-hosts` is modeled, so no authorization is created in
this slice and every other operation remains `operation-context-unmodeled`
before writes. No CLI invokes it. A fake-runner-tested internal handoff now
persists strict `deploy-scylla-vms.ansible-operation-execution/v1` at the
matching operation path. It revalidates that exact checkpoint, durably records
one deterministic step as started before invoking a strict adapter to the
existing controlled Ansible service,
consumes non-read-only authorization once, and stores only bounded strict result
digests/states. Started, failed, timed-out, interrupted, unreachable, or
malformed outcomes require manual recovery and cannot be retried automatically.
The adapter rechecks canonical rendered runtime files and exact current
inventory/trust/readiness/catalog/source bindings, rebuilds the allowlisted
command-intent digest, and accepts only strict per-playbook parsed evidence; it
does not expose paths, command arguments, environment controls, raw output, or
arbitrary variables to callers. A narrow internal coordinator now derives the
canonical cluster paths from cluster identity, loads and revalidates the
operation context plus every binding/journal/authorization/execution and local
desired/observed/inventory/trust/source/catalog artifact, reconstructs the
request and ephemeral allowlisted variables, and checks every persisted context,
request, plan, and binding digest before any tool probe. It then validates the
rendered controller files, probes the exact sibling
`ansible-playbook`/`ansible-inventory` pair, recomputes machine inventory
readiness and the exact bound plan, constructs that adapter, and calls the
handoff for exactly one step. Its independently versioned
`deploy-scylla-vms.ansible-operation-coordinator-report/v1` projection contains
only step indices, bounded states, context and execution schemas/digests, and
retry/recovery flags. The bounded read-only `check-jump-hosts` context schema
now reconstructs default and explicit selectors/timeouts that satisfy its
allowlist. Every other operation has the stable `operation-context-unmodeled`
blocker before tool probing or durable intent. The coordinator and handoff
remain disconnected from the CLI and public mutating workflows. A narrow
internal orchestrator now loads that prepared immutable context, proves the
operation and effective class are exactly read-only with no authorization, and
drives the fixed `inventory-preflight` then `connectivity-check` sequence by
calling the one-step coordinator once per next durable step. It reloads and
validates the execution companion between calls, continues only an exact
succeeded prefix, bounds calls by the immutable two-step plan, and never retries
a started or uncertain attempt. After each strict parser result, the controlled
adapter now appends only address-free semantic facts to owner-only
`deploy-scylla-vms.ansible-operation-evidence/v1` at
`<cluster-root>/operations/<operation-uuid>.ansible-operation-evidence.json`
before returning its seven-field receipt. Inventory preflight retains exact
parity/status/counts and observation/inventory provenance; connectivity retains
only stable IDs, bounded host classifications, and exact requested role/port TCP
pair outcomes. The handoff requires the matching persisted projection digest
before terminal success; a missing, mismatched, or failed post-effect write is
manual-recovery/no-retry. Its independently versioned
`deploy-scylla-vms.ansible-check-jump-hosts-orchestration-report/v1` reports
`steps-succeeded` with `semantic-evidence-ready` only when both exact entries
reconstruct the dynamic public-v2 facts; legacy digest-only success remains
`post-verification-pending`, and uncertain execution remains
`execution-stopped`/`not-reached`. A separate subprocess-free internal
post-verifier now reloads every canonical checkpoint and current local
provenance, reconstructs the exact address-free successful result, and first
persists immutable `deploy-scylla-vms.ansible-operation-finalization/v1` at
`<cluster-root>/operations/<operation-uuid>.ansible-operation-finalization.json`.
It then appends exact `VERIFY/completed` evidence and advances the common v1
journal to `succeeded/JOURNAL`. An exact finalization-only or VERIFY-journal
prefix is recoverable without duplicate events; terminal re-entry performs no
writes. Any failed, unreachable, timed-out, interrupted, malformed, or started
execution remains manual-recovery state and cannot be finalized. This internal
path does not replace the existing public no-write workflow or claim broader
host health. A fake-runner-tested internal lifecycle coordinator now composes
the existing preparation, exact two-step orchestration, semantic verification,
and finalization APIs. A separate subprocess-free internal initiation API now
owns creation of its prerequisite common journal for only modeled read-only
`check-jump-hosts`. Under the matching operation-named cluster lock, it writes
one owner-only generation-1 `IN_PROGRESS/PLAN` record containing the canonical
operation/cluster identities and normalized non-secret request digest, with no
checkpoint evidence until preparation resolves the exact plan. Preparation
then appends that PLAN evidence as generation 2 before creating the binding.
Exact untouched initiation state is reusable; active-operation conflicts,
cross-cluster UUID replay, changed requests, companions, or advanced history
fail closed without deletion or rollback. Its independently versioned
`deploy-scylla-vms.ansible-operation-initiation-report/v1` projection contains
only created/reused/blocked state, operation UUID/kind/classification, explicit
public stable-ID selectors, counts, status/phase, blockers, and digests. The
lifecycle accepts a typed request only until immutable context can reconstruct
it, resumes exact partial checkpoints and finalization prefixes, and reports
`deploy-scylla-vms.ansible-check-jump-hosts-lifecycle-report/v1`. Terminal
success makes no write or tool call; wrong kind/class, drift, forbidden
authorization, missing prerequisites, legacy digest-only completion, and every
uncertain execution stop without retry. It remains internal and leaves the
public write-free checker unchanged. A final narrow internal one-call
coordinator now composes that initiation owner with the lifecycle under the
same already-held operation-named lock. Fresh calls create generation 1 and
then drive preparation through terminal verification; exact generation-1 and
all later supported prefixes resume without reacquiring the lock. Advanced
prefixes skip re-entering the deliberately initial-only initiation owner and
pass directly to lifecycle revalidation. Its strict
`deploy-scylla-vms.ansible-check-jump-hosts-operation-report/v1` projection
contains only bounded initiation/lifecycle/stage states, counts, retry/recovery
truth, schemas, and digests. Terminal re-entry remains zero-write/zero-tool,
and no CLI invokes this composition.
`check-jump-hosts` is the second functional
operation: it validates canonical persisted observation/inventory/trust evidence,
runs preflight first, and then checks only explicitly selected jump stable IDs.
The internal `evidence-collect` API now returns a strict allowlisted host summary
without writing. An explicitly approved matching-lock store may persist only its
versioned, provenance-bound aggregate at `<cluster-root>/logs/evidence.json`;
no public operation requests that write yet.
The internal `base-os` source accepts only exact Ubuntu 24.04 image evidence on
OCI `amd64` (guest `x86_64`) or OCI/guest `aarch64`. It gathers guest facts,
refuses unsupported or mismatched evidence, installs only `ca-certificates`,
`python3-debian`, `systemd-timesyncd`, `tar`, and `unzip`, enables
`systemd-timesyncd`, and reports Ubuntu's reboot-required marker without
rebooting. Its strict result projection retains no raw module output. New
desired state refuses the former unsupported Oracle Linux baseline and all
other operating systems; persisted desired state is not silently migrated.
The internal `jump-host-configure` source hardens exactly one validated jump
stable ID after current Ubuntu `base-os` evidence, complete trust, and
inventory-derived RFC 1918 ProxyJump routes. It installs only
`/etc/ssh/sshd_config.d/00-deploy-scylla-vms.conf` with password/root login
disabled, public-key-only authentication, local TCP forwarding limited to
assigned private host:22 routes, and no agent/X11/tunnel/stream-local
forwarding or host-key bypass. Strict
`deploy-scylla-vms.ansible-jump-host-configure/v1` results omit addresses and
raw sshd output. No public operation invokes it yet.
The internal Scylla-only `storage-discover` source uses a bounded read-only
module to correlate stable by-id/serial/WWN evidence, block/NVMe topology,
root/boot ancestry, mounts, holders, signatures, optional-tool availability,
and ownership-marker presence. Its strict
`deploy-scylla-vms.ansible-storage-discovery/v1` parser binds results to exact
observation, inventory, host-manifest, and storage-policy provenance and keeps
sensitive device/provider identifiers internal. It does not preflight, prepare,
format, wipe, partition, mount, activate, or assemble storage.
The internal `storage-preflight` API reconciles that exact discovery with the
persisted desired policy and Terraform storage manifest for explicitly limited
Scylla stable IDs. Its independently versioned return-only result classifies
clean-new, exactly owned no-op, reviewed-wipe-required, and blocked devices,
publishes only hashed device identities, and binds a preparation-intent digest
to the complete provenance and selected set. Its packaged playbook only reports
the validated controller projection; it performs no device access or write.
The internal Scylla-only `storage-prepare` source accepts exactly one stable-ID
target and an owner-only typed payload bound to the current observation,
inventory, discovery, policy, preparation intent, operation ID, and exact
device-set digest. It refuses check mode and blocked storage, requires separate
digest-bound wipe consent, re-runs root/boot/mount/signature/holder/by-id checks
immediately before writing, and leaves exactly owned storage unchanged. The
fixed policy creates one XFS filesystem directly or RAID0 over the exact
authorized set, mounts only `/var/lib/scylla` by filesystem UUID, and writes the
ownership marker only after mount success. Its strict result records completed
steps, the first irreversible action, post-action verification, and whether
manual recovery is required; destructive writes are never reported as
rollbackable.
The internal read-only `storage-postcheck` source immediately verifies one
prepared Scylla target against current desired, Terraform, inventory, trust,
discovery, preflight, and preparation provenance. It fails closed on tool,
identity, membership, RAID, XFS, UUID, fstab, mount, capacity, permission,
signature, holder, marker, or provenance conflicts and reports only hashed
device identities, digests, bounded blockers, and readiness for Scylla. It
never repairs, remounts, or writes.
The source-available Scylla-only `storage-retire` source accepts exactly one
stable-ID target after current owned discovery, postcheck, observation,
inventory, and trust evidence. It refuses check mode, an active Scylla
service, remaining membership, blocked storage, and device-identity drift,
requires separately bound wipe consent only for `delete`, and never wipes
retained or ephemeral media. It unmounts `/var/lib/scylla`, removes the UUID
fstab entry, and deactivates the exact RAID0 array when present. Strict
`deploy-scylla-vms.ansible-storage-retire/v1` results hash device identities
and report the first irreversible step, manual-recovery requirement, and
explicit not-performed Terraform, VM, and Scylla start/stop items. No public
operation invokes it yet.
The source-available `service-converge` slice reconciles only PLAN-owned
systemd units on one Ubuntu 24.04 stable ID after current `base-os` and
role-appropriate current install evidence. It may enable/start
`systemd-timesyncd` and never unmasks or starts Scylla, Manager, exporters,
or the monitoring stack. Check mode reports `not-predicted`. Strict
`deploy-scylla-vms.ansible-service-converge/v1` results report per-unit
desired/observed state, applied flags, explicit not-performed starts, and
redacted blockers. No public operation invokes it yet.
The source-available `scylla-cluster-shutdown` slice validates an explicitly
authorized full-cluster guest shutdown after current `scylla-health` and
observation/inventory/trust evidence. PLAN-cited 2026.2 administrator pages do
not publish a reviewed drain-then-stop order, so the slice inspects
`scylla-server` only, refuses check mode, and never drains, stops, masks,
decommissions, wipes storage, or runs Terraform. Manager quiesce is not
invented while Manager remains unstarted; explicit not-applicable
authorization is required. Strict
`deploy-scylla-vms.ansible-scylla-cluster-shutdown/v1` results hash Host IDs,
report per-node drain/stop/mask as not-performed, and retain mutation/recovery
boundaries plus redacted blockers. No public operation invokes it yet.
The source-available `os-upgrade-preflight` slice performs a serial-one,
check-mode-safe, read-only inspection of one exact role-aware stable ID after
current observation/inventory/trust, `base-os`, role package/configuration, and
availability evidence. Scylla targets additionally require current storage,
configuration, complete cross-view health, and explicit replication/quorum/
capacity/backup/topology rolling gates. It checks only Ubuntu's reboot-required
marker, `dpkg --audit`, fixed package-lock inodes through `/proc/locks`, Linux/
architecture facts, and caller-policy-bound root/boot free space. PLAN defines
no target transition beyond the current Ubuntu 24.04 baseline, no approved
kernel allowlist, and no safe read-only proof of package currency/repository
state, so same-release requests are `undefined`, every other target is
`unsupported`, and all results remain blocked with those checks explicit. It
never runs APT mutation, `do-release-upgrade`, reboot, service changes, OCI,
Terraform, or VM replacement. Strict
`deploy-scylla-vms.ansible-os-upgrade-preflight/v1` results omit addresses and
raw package output. No public operation invokes it yet.
The source-available `os-upgrade-in-place` slice validates one exact
digest-authorized sensitive target after current successful, explicitly
rolling-eligible preflight evidence. It refuses same-version requests,
unsupported current/target OS, architecture conflicts, stale provenance, and
ineligible preflight. Because PLAN approves neither a target transition nor a
role-safe shutdown/reboot sequence, its strict
`deploy-scylla-vms.ansible-os-upgrade-in-place/v1` result is always blocked with
mutation boundary `not-started`, package/source/service/reboot/kernel/config
actions `not-performed`, and recovery not required. Scylla targets additionally
report `shutdown-sequence-unreviewed`; every target reports
`target-transition-unapproved`. The playbook contains no package, service,
reboot, configuration, storage, Terraform, VM, or cloud mutation and never
automatically retries. Source availability means this refusal contract is
reviewed and packaged, not that an OS upgrade is implemented. No public
operation invokes it.
The source-available `os-reprovision-prepare` slice validates one exact
destructive-scope immutable replacement intent after current role-aware
`os-upgrade-preflight`, observation/inventory/trust/`base-os`, package,
configuration, storage, health/lifecycle, and caller-supplied offline
provider/image evidence. It preserves the stable logical ID, hashes the current
provider and old/new image identities, requires the future provider identity to
change, and records explicit storage disposition. Scylla targets remain blocked
unless independently reviewed membership handling is complete and always
delegate to `replace-node`; Manager, monitoring, and jump targets report their
unimplemented restore, re-registration, target refresh, route, and retrust
requirements. Because no target transition or Terraform replacement
orchestration is approved, strict
`deploy-scylla-vms.ansible-os-reprovision-prepare/v1` evidence is always
validation-only and blocked before mutation, with every Terraform/VM/storage/
package/service/membership/configuration/reboot action `not-performed`,
automatic retry false, and recovery not required. It refuses check mode and
contains no provider call or host mutation.
Source availability means this executable refusal contract is packaged, not
that reprovision is implemented. No public operation invokes it.
The source-available `os-upgrade-postcheck` slice is the thirty-first
production catalog source. It is read-only, check-mode-safe, exact-one-target,
serial-one, and fatal. It requires an exact digest-bound source result from
either
`os-upgrade-in-place` or `os-reprovision-prepare` plus current
observation/inventory/trust, `base-os`, package, configuration, storage,
service, route, and role-health evidence. Every currently supported source
result proves `mutation_boundary=not-started` and `applied=false`, so every
postcheck fails closed with `source-upgrade-not-performed`; no supported path
can currently produce successful upgrade evidence. The bounded host module may
inspect only OS/version/architecture, `dpkg --audit`, exact package versions,
kernel-release policy, reboot-required state, and fixed service policy. Strict
`deploy-scylla-vms.ansible-os-upgrade-postcheck/v1` evidence reports source and
provenance digests, transition comparison, per-gate status, verification
coverage, and mutation/remediation false without addresses, raw command or
package output, device paths, provider output, secrets, or environment. It
never runs APT mutation, reboots, changes services/configuration/storage/trust,
contacts OCI/Terraform, or remediates. Source availability does not make OS
upgrade operational, and no public operation invokes this source.
The source-available internal `scylla-install` installs only an explicit exact
ScyllaDB
2026.2 package version on one current Ubuntu 24.04 Scylla stable ID after
successful base-OS and storage-postcheck evidence. It pins the official signed
repository and 2026 signing-key artifact, masks `scylla-server` before package
work, prevents package-script startup, verifies all seven exact package
versions, and leaves the service masked and inactive. It performs no Scylla
configuration, topology, storage, tuning, Manager, reboot, or startup. Check
mode reports `not-predicted`. The pinned upstream role is retained for future
configuration provenance but is not invoked for installation because its
current Ubuntu path exceeds these boundaries.
Its vendored public key is authenticated by the full OpenPGP fingerprint in the
official repository's signed `InRelease`, matching immutable official
documentation and installer-source key-ID references. Python validates the
vendored artifact's SHA-256, full primary/subkey fingerprints, UID, and absence
of revocation packets before building install intent; hosts make no key download.
The source-available `scylla-configure` slice then uses wrapper-owned templates
to atomically manage only the exact reviewed keys in `/etc/scylla/scylla.yaml`
and `dc`, `rack`, and `prefer_local=true` in
`/etc/scylla/cassandra-rackdc.properties`, both root-owned mode `0644`. It
requires exact current base-OS, storage-postcheck, install, observation,
inventory, trust, private-address, topology, and package-version evidence.
Initial seeds use one deterministic stable ID; growth retains healthy persisted
seeds and expands to at most three across racks, while add/replace excludes the
joining target as the sole seed. Cluster name and datacenter/rack relabeling
after initial configuration are refused. The service remains masked/inactive,
check mode reports `not-predicted`, and strict address-free results truthfully
report `runtime_validation_performed=false`; this slice does not start,
bootstrap, or health-check Scylla.
The source-available `scylla-bootstrap` slice starts exactly one stable-ID
Scylla target in an explicit `initial-seed` or `join-existing` mode. It requires
reviewed digest-bound operation, desired-spec, observation, inventory, trust,
storage, install, configuration, topology, and seed evidence. Initial seed
requires a proven empty cluster and exact deterministic seed identity; joining
requires healthy surviving members/seeds, target absence, capacity/topology/
schema gates, and exact add/scale intent. It revalidates immediately before its
systemd unmask/start boundary, waits boundedly for CQL and argv-form `nodetool`
membership/streaming/schema evidence, and emits only strict address-free
`deploy-scylla-vms.ansible-scylla-bootstrap/v1` results. Failure never triggers
automatic destroy or retry; the node is remasked only when it is safe and
proven never joined. The source-available read-only `scylla-health` slice
normally queries every current Scylla stable ID and reconciles each local Host
ID against every normalized ring view. It uses only fixed argv-form `nodetool`
`info`, `status`, `describecluster`, and `netstats`, service state, and local
API/CQL TCP checks. Its strict address-free result binds observation,
inventory, trust, and storage evidence; rejects missing, extra, duplicate,
transitional/down, topologically inconsistent, schema-disagreeing, or streaming
members; and reports replication, quorum, and Manager backup checks as
unknown/not performed rather than healthy. This remains an internal
library/service integration: `show --live` is unavailable and no public
operation invokes it. The source-available `scylla-remove-live` slice
decommissions exactly one reachable Up Normal stable-ID target. It requires
fresh full-cluster health plus independently validated, all-passed replication,
quorum, post-removal capacity, and backup-policy evidence; exact logical,
Host-ID, provider, datacenter/rack, observation, inventory, trust, storage, and
configuration bindings; an exact desired removal intent; and narrow destructive
authorization for the intended post-removal topology. It revalidates target
identity from the target and a healthy survivor immediately before the argv-form
`nodetool decommission` boundary, then polls a surviving coordinator for target
absence, survivor Up Normal state, schema agreement, idle streaming, and exact
topology. Failures require reviewed recovery and never stop or destroy the VM,
wipe storage, edit desired state, or run Terraform. No public operation invokes
this source; infrastructure deletion remains unavailable. The source-available
`scylla-remove-dead` slice runs only on one explicitly selected healthy survivor,
never the unavailable target. It requires independent SSH/service/provider
unreachability, unchanged stable/Host/provider identity, consistent survivor
views retaining the exact dead Host ID, healthy schema-agreed idle survivors,
all-passed replication/quorum/capacity/backup evidence, exact post-topology, and
narrow digest-bound destructive authorization. It immediately revalidates the
required survivor quorum, runs argv-form `nodetool removenode <host-id>`, checks
`nodetool removenode status`, and proves exact ring postconditions without
automatic force completion or blind retry. Results use
`deploy-scylla-vms.ansible-scylla-remove-dead/v1`; a started, failed, timed-out,
or interrupted command requires journaled recovery review.
The source-available `scylla-replace-dead` slice runs on exactly one newly
provisioned replacement target retaining the failed node's stable logical ID
but using a distinct provider identity. It requires quorum-consistent DN
evidence for the old Host ID, independent old-target unreachability, no prior
`removenode`, empty prepared storage, exact ScyllaDB 2026.2 patch/config/
topology/seeds, current observation/inventory/trust, passed replication/quorum/
capacity/backup gates, and narrow digest-bound authorization. It immediately
revalidates survivor and replacement state, atomically adds only
`replace_node_first_boot: <dead-host-id>` while the service is masked/inactive,
then uses one systemd unmask/start boundary. Bounded survivor `gossipinfo`,
`status`, `describecluster`, and `netstats` polling must prove a new Host ID is
UN, the old Host ID is absent, topology and schema agree, and streaming is idle.
It never runs `removenode`, repair, force, infrastructure, or storage mutation;
the first-boot key remains after success. Strict
`deploy-scylla-vms.ansible-scylla-replace-dead/v1` evidence requires later
repair/Manager proof unless complete enabled RBNO evidence makes repair
unnecessary.
The source-available `scylla-repair` slice runs on exactly one validated
Scylla stable ID for either mandatory post-replacement repair or an explicitly
reviewed post-bootstrap repair. It requires current full-cluster UN topology,
schema agreement, idle streaming, exact target Host ID/DC/rack/2026.2 version,
current observation/inventory/trust/config/storage evidence, passed capacity
and quorum gates, no competing operation, and narrow digest-bound
authorization. Complete enabled RBNO replacement evidence produces a strict
no-op; version alone never does. Otherwise it immediately revalidates with
fixed read commands, runs only foreground argv-form `nodetool repair`, and
requires post-health plus no pending repair/compaction work. Strict
`deploy-scylla-vms.ansible-scylla-repair/v1` output records started/completed
boundaries without raw output or addresses. Direct command completion is
operational rather than cryptographic proof, so successful direct evidence
still requires explicit review; timeout/interruption forbids automatic retry.
The source-available `scylla-cleanup` slice runs the fixed foreground
`nodetool cleanup` command on exactly one Python-authorized eligible target
after a completed healthy add-node or scale-out topology change. Current
full-cluster health must prove exact post-expansion topology, all members UN,
schema agreement, and no streaming; separate current disk/compaction headroom,
repair/RBNO when required, provenance, competing-operation, and narrow
authorization gates must also pass. The 2026.2 target set is pre-existing
survivors plus, for multi-node scale-out only, earlier joined nodes; the last
joined node is never targeted. Fixed read commands immediately revalidate the
cluster, then bounded polling requires no pending compaction/cleanup work and
healthy post-state. Strict
`deploy-scylla-vms.ansible-scylla-cleanup/v1` evidence retains only status,
stable ID, hashed Host ID, source/repair and pre/post health digests, command/
pending-work boundaries, recovery truth, and bounded blockers. Failure,
timeout, or interruption prohibits automatic retry or advancing to another
node.
The source-available `jump-host-configure` slice hardens exactly one jump
stable ID for ProxyJump after current Ubuntu `base-os`, complete trust, and
exact inventory routes. It is serial-one, jump-only, and check-mode
non-predictive.
The source-available `manager-agent` slice installs one exact ScyllaDB Manager
3.12 `scylla-manager-agent` package on one Ubuntu 24.04 Scylla stable ID after
current successful `base-os` and `scylla-install` evidence. It reuses the
already-authenticated 2026 signing key because that key signs the official
Manager 3.12 InRelease, pins the official Ubuntu Manager 3.12 repository, and
leaves the agent disabled/inactive. It does not write `auth_token`, run
`scyllamgr_agent_setup`, start the agent or Scylla, or claim server-to-agent
reachability. Check mode reports `not-predicted`. Strict
`deploy-scylla-vms.ansible-manager-agent/v1` results keep configuration, token,
helper-slice, and reachability as explicit false/not-performed. No public
operation invokes it yet. The internal deploy-only execution owner can now
consume the exact mapped-position-16 authorization, execute the complete
canonical Scylla stable-ID scope serial-one, and persist redacted
generation-guarded execution plus immutable-prefix semantic evidence. It
permanently refuses automatic retry after any uncertain started attempt and
keeps the VERIFY journal and prior plans/reconciliations unchanged. The
internal post-execution reconciliation now requires complete ordered semantic
success for that exact scope, preserves the immutable 21-position mapping, and
advances at most the immediate next mapped gate without configuring agents,
tokens, or Manager reachability. Local `show` validates its bounded immutable
record; no public operation invokes the reconciliation.
The next internal deploy-only authorization boundary now consumes only that
exact post-Manager-agent reconciliation and derives mapped position 17
`monitoring-agent` for the complete canonical Scylla stable-ID set. It binds
Ubuntu 24.04, current Scylla-install evidence, the exact ScyllaDB 2026.2
`scylla-node-exporter` package/source intent, disabled/inactive service state,
and listen policy `not-started`; ordinary interactive or PLAN-permitted
`cli-yes` approval is required. The immutable owner-only authorization remains
unconsumed and execution-unavailable, and local `show` validates it without
running Ansible or exposing package, repository, key, command, variable,
address, route, port, path, or secret values. No public operation invokes it.
The internal execution owner can now consume that exact mapped authorization,
execute the complete canonical Scylla stable-ID scope serial-one, and persist
redacted generation-guarded execution plus immutable-prefix semantic evidence.
It accepts only strict installed/no-change results with node exporter disabled/
inactive and listen policy `not-started`, permanently refuses automatic retry
after any uncertain started attempt, and preserves prepared recovery plus exact
zero-process/zero-write completed re-entry. The VERIFY journal, authorization,
post-Manager-agent reconciliation, and prior plans remain unchanged; local
`show` validates both companions, and no public operation invokes the owner.
The internal post-execution reconciliation now requires complete ordered
semantic success for that exact scope, preserves the immutable 21-position
mapping, marks only mapped `monitoring-agent` succeeded, and advances at most
the immediate next active gate. It keeps exporter/stack reachability and health
unknown, does not generate monitoring targets, and leaves the VERIFY journal
and all prior records unchanged. Local `show` validates the bounded immutable
record; no public operation invokes the reconciliation.
The internal mapped `monitoring-targets` authorization owner accepts only the
matching held deploy lock and normalized ordinary interactive or `cli-yes`
approval. It reloads and exactly reproduces the post-Monitoring-agent
reconciliation, authorizes only mapping position 18 for the single canonical
monitoring host, validates current Ubuntu 24.04/base-OS, Monitoring 4.16.0
stack, Manager-server, Manager-agent, and Monitoring-agent evidence, and
rebuilds the deterministic official four-file target intent from canonical RFC
1918 inventory. Its immutable owner-only record retains only bounded
counts/enums/booleans/stable IDs and digests, never file names, paths, contents,
labels, addresses, ports, commands, variables, auth/configuration values, or
secrets. Destructive and narrow proofs are refused; authorization remains
unconsumed and no target file, execution record, process call, journal change,
finalization, or CLI/public wiring is added.
The internal execution owner can now consume that exact mapped authorization,
run only the single canonical monitoring target serial-one, and persist
redacted generation-guarded execution plus immutable-prefix semantic evidence.
It accepts only exact Monitoring 4.16.0 generated/no-change four-file intent
results with listen policy `not-started`, scrape readiness `not-performed`, and
all service/container/exporter/auth/public-bind/Compose/secret actions absent.
Any uncertain started attempt permanently requires manual recovery and forbids
retry; prepared recovery remains safe before invocation and exact completion
re-entry is zero-process/zero-write. The VERIFY journal, authorization,
post-Monitoring-agent reconciliation, and historical plans remain unchanged;
local `show` validates both records and no public operation invokes the owner.
The internal post-execution reconciliation now requires that exact consumed
terminal success and complete Monitoring 4.16.0 four-file semantic evidence,
preserves the immutable 21-position mapping, and marks only mapped
`monitoring-targets` succeeded. It evaluates only immediate sensitive
`manager-tasks`, which remains blocked because its explicit task action is
unmodeled and its packaged source is validation-only while Manager is
inactive, unregistered, and has no configured backend. It does not infer
backup/repair readiness, invoke `sctool`, start/unmask Manager, configure a
backend, or register a cluster. The VERIFY journal and prior records remain
unchanged; local `show` validates the bounded immutable record and no public
operation invokes the reconciliation.
The internal Manager-activation planning bridge now preserves that blocked
historical mapping while persisting separate immutable, owner-only activation
context and plan companions. It accepts only canonical cluster/operation
identity plus the matching held deploy lock, reloads the exact full chain, and
derives the one Manager target and complete Scylla Manager-agent scope. Its
ordered plan records backend configuration, Manager service
activation/readiness, cluster-registration/auth-token handoff, and only then
mapped `manager-tasks`. The first three boundaries are source-unavailable; all
remain authorization-required, evidence-required, blocked, and not-performed.
The packaged `manager-tasks` source remains source-available but
validation-only, and deploy still has no deterministic explicit action, so the
bridge records `manager-tasks-action-unmodeled` rather than choosing `inspect`.
Exact context-only recovery and zero-write reuse are supported, local `show`
validates both redacted companions, and the VERIFY journal and historical
records remain unchanged. No authorization, execution, runner, CLI/public
wiring, or backend/token/config/task value is introduced.
The internal Manager backend context/plan now adopts the official recommended,
versioned `local-one-node` ScyllaDB backend on the Manager VM. It forbids using
the managed data cluster, forbids CQL network ingress, fixes loopback-only
contact with default CQL port 9042 and a ScyllaDB 2026.2 target, and uses no
backend credentials/TLS secrets for local loopback v1. Future Manager-agent
token intake remains environment-only. Only the backend-mode blocker is
resolved: package availability, storage/tuning/capacity, setup behavior,
configuration, schema/keyspace, recovery, and mutating source stages remain
explicitly blocked or unknown.
The new source-available `manager-backend-preflight` is read-only,
Manager-only, exact-one-target, serial-one, fatal, and check-mode-safe. It
requires current Ubuntu 24.04/base-OS, Manager 3.12 install, activation/backend
plan, inventory/trust/readiness, and source provenance. It inspects only bounded
OS/architecture, CPU/memory/root capacity, approved-mount counts, fixed package
and service states, reboot requirement, and loopback availability. Strict
`deploy-scylla-vms.ansible-manager-backend-preflight/v1` evidence is redacted
and can report only readiness for later installation planning; backend
operational readiness remains not-performed. It does not query repositories,
read configuration content, connect to CQL/network services, install packages,
run `scyllamgr_setup`, write configuration, create schema, or start services.
The internal operation-bound owner now revalidates the complete immutable
local-one-node planning chain and current controller/toolchain state, derives
the exact Manager target and fixed read-only intent, records durable execution
intent, and persists strict redacted semantic evidence before terminal success.
Started uncertainty, process/result failure, semantic mismatch, drift, or
post-call persistence failure requires manual recovery and permanently forbids
automatic retry; exact completed re-entry is zero-process/zero-write.
Its immutable reconciliation evaluates only later installation-planning gates.
Package availability, storage/tuning suitability, exact capacity policy, setup,
schema/keyspace, recovery, and mutating-source requirements remain explicit
unknowns or blockers, and backend readiness remains not-performed. The VERIFY
journal and prior records do not change, and there is no mutation authorization
or public/CLI wiring.
The internal local-backend installation context/plan now binds that exact
preflight chain and models nine separate future boundaries: package install,
dedicated-storage allocation, storage preflight/prepare/postcheck, local Scylla
configuration/tuning, one-node bootstrap/start/health, Manager backend-file
configuration, and schema/keyspace creation/verification. It can safely
identify the Manager's dedicated Terraform Block Volume by digest, but never
persists provider/device identity and never falls back to root/boot storage or
generic free space. Missing or unidentifiable storage records
`dedicated-backend-storage-unmodeled`.
Only the authenticated ScyllaDB 2026.2 repository/key reference is reusable.
The persisted installation plan keeps nine ordered not-performed boundaries
immutable. At its creation, only the first package-install boundary is
source-available and can become `evidence-ready-authorization-required`; later
sources are introduced through separate planning records rather than rewriting
that plan. Existing Scylla-role storage/configure/bootstrap owners are not
reused. The separately packaged `manager-backend-local-install` source
implements that first boundary for one exact Manager target. It installs the exact
authenticated seven-package ScyllaDB 2026.2 set, suppresses maintainer-script
startup, and leaves `scylla-server` masked/inactive. It requires current
base-OS, Manager-server, backend-preflight, installation-plan, dedicated-volume,
observation/inventory/trust, repository/key, and source provenance. Check mode
reports `not-predicted`.
Strict `deploy-scylla-vms.ansible-manager-backend-local-install/v1` evidence
contains only stable role/platform/status values and package/repository/key/
source/command digests. Storage/filesystem/mount mutation, tuning, setup,
configuration, CQL/schema/keyspace, Manager configuration/registration/tasks,
token work, and service enable/start remain false or not-performed. The internal
operation-bound authorization owner reproduces that exact current plan and full
provenance chain, accepts only ordinary interactive or PLAN-permitted `cli-yes`
approval, refuses destructive/narrow proof and stale or drifted planning, and
persists one redacted immutable authorization with zero-write exact reuse.
The internal execution owner now consumes that authorization only through a
durable `started` record, invokes the hash-checked source once for the exact
Manager target, and persists generation-guarded execution plus immutable-prefix
semantic evidence. Strict success requires exact package/repository/key/source/
command provenance, installed/no-change state, masked/inactive Scylla, and all
forbidden actions absent. Prepared recovery is safe only before invocation;
every uncertain started outcome is permanent manual-recovery/no-retry, while
exact completed re-entry is zero-process/zero-write. The VERIFY journal,
authorization, and plans remain unchanged, local `show` validates both records,
and no CLI/public wiring exists.
The internal post-install reconciliation owner now requires that exact terminal
success and consumed execution authorization, revalidates the complete package
and planning chain, and persists one immutable redacted
`deploy-scylla-vms.ansible-deploy-post-manager-backend-local-install-reconciliation/v1`
companion. It marks only package installation succeeded, preserves all nine
installation boundaries and the VERIFY journal, and derives the immediate
`local-storage-allocation` boundary from the immutable plan. That boundary
remains blocked in that reconciliation, which is never rewritten. No later
storage, tuning, setup, configuration, schema, or recovery boundary advances.
The separate Manager-backend storage allocation/discovery planner now
revalidates that full chain and persists immutable owner-only context and plan
records. It derives only one exact dedicated Manager-role Block Volume whose
stable/provider identity and attachment match desired state, Terraform input,
the observed storage manifest, inventory, trust, and readiness. Root/boot
fallback, local NVMe, arbitrary attachments, path/order selection, generic
free space, and shared Scylla storage are forbidden. Missing, ambiguous, or
path-only identities produce no discovery scope. Requested/observed bounded
GiB, count, and backend facts do not prove capacity: policy remains `unknown`
and adequacy `not-evaluated`.
The distinct source-available `manager-backend-storage-discover` contract is
Manager-only, exact-one-target, serial-one, fatal, check-mode-safe, and
read-only. It correlates bounded Linux block, mount, signature, holder,
ownership-marker, and topology facts against the exact Terraform manifest
through non-path identities. Strict
`deploy-scylla-vms.ansible-manager-backend-storage-discovery/v1` results expose
only the stable ID, bounded count/size/type/signature/ownership/status enums,
blockers, and hashed device/topology/manifest/provenance digests. Raw paths,
serials, UUIDs, addresses, provider IDs, commands, output, environment,
credentials, and secrets are absent. It never writes, wipes, partitions,
creates RAID/filesystems, mounts, edits fstab, configures or starts services,
or accesses CQL.
The internal operation-bound owner now derives the sole eligible Manager
target and exact manifest-bound variables, durably records `started`, invokes
only that hash-checked read-only source through the controlled service, and
persists independently versioned execution and immutable semantic-evidence
companions. Uncertain or failed started calls are permanent manual-recovery/
no-retry; exact completion re-entry is zero-process and zero-write. Its
subprocess-free reconciliation marks only strict discovered evidence
succeeded, keeps blocked device evidence blocked, and leaves capacity adequacy
`unknown`, storage preflight/preparation unavailable, wipe safety
`not-evaluated`, and owned-noop `not-inferred`. The VERIFY journal and prior
records remain unchanged; no authorization, mutation, service/configuration,
CLI, or public wiring is added. The following independently versioned boundary
implements the separately reviewed Manager-backend storage-preflight plan.
That planning boundary now persists separate immutable Manager-backend storage
preflight context/plan records after revalidating the complete successful
allocation/discovery chain. The approved layout is one whole dedicated Block
Volume, XFS, fixed `/var/lib/scylla` ownership, required fstab/mount intent,
and a Manager-local one-node marker; RAID, partitions, local NVMe, root/boot
fallback, arbitrary attachment selection, and shared Scylla storage are
forbidden. Desired, Terraform-observed, and discovered GiB/count/type plus
manifest/device identity must match exactly. This proves only operator-selected
allocation conformance; long-term capacity sufficiency remains `not-proven`
and operator-policy-bound.
The source-available `manager-backend-storage-preflight` contract is read-only,
Manager-only, exact-one-target, serial-one, fatal, and check-mode-safe. It
classifies only `owned-noop`, `prepare-required`, or `blocked`, permits an exact
blank unowned device to require preparation without wipe, and keeps any
signature wipe requirement separate for future explicit consent. A signature
on unowned storage is foreign and blocks preparation. Foreign ownership,
unexpected mount/fstab/marker state, busy/root/boot/ambiguous devices, and
identity/size/topology conflicts also block. Strict
`deploy-scylla-vms.ansible-manager-backend-storage-preflight/v1` evidence
contains only bounded enums/counts/booleans/blockers and hashed device-set,
preparation-intent, and provenance identities.
The operation-bound owner derives the exact target, desired policy, manifest,
discovery projection, variables, and anchored command from current canonical
state, durably records `started`, and invokes only that hash-checked read-only
source. It persists generation-guarded execution and immutable-prefix semantic
evidence records; every uncertain or failed started outcome is permanent
manual-recovery/no-retry, while exact completed re-entry performs no process
call or write. Immutable reconciliation marks preflight succeeded, keeps
`owned-noop` out of authorization, leaves blocked results blocked, and derives
only an exact `prepare-required` scope with a separate wipe-required subset.
Capacity sufficiency remains `not-proven` and cannot satisfy later service
health/capacity gates. Exact `prepare-required` scope is now
`evidence-ready-authorization-required`, and the destructive
`manager-backend-storage-prepare` source is available for the single whole-
device XFS, stable-UUID fstab, `/var/lib/scylla` mount, root ownership/mode,
and Manager marker boundary. It revalidates immediately before its first
write, keeps wipe consent separate and digest-bound, and emits only strict
redacted results; `owned-noop` and blocked storage are never executed. No
operation authorization/execution owner, journal transition, CLI, or public
wiring invokes it yet.
The source-available `manager-server` slice installs exact ScyllaDB Manager
3.12 `scylla-manager-server` and `scylla-manager-client` packages on one
Ubuntu 24.04 manager stable ID after current successful `base-os` evidence. It
reuses the same authenticated 2026 signing key and official Ubuntu Manager
3.12 repository, masks `scylla-manager` before package work, and leaves the
service masked/inactive. Official docs configure a Scylla backend and register
clusters only after packages; this slice does not implement the selected
backend, write
`scylla-manager.yaml`, run `scyllamgr_setup`, persist an environment token, or
start Manager. Check mode reports `not-predicted`. Strict
`deploy-scylla-vms.ansible-manager-server/v1` results keep
`backend_configured`, `configuration_performed`, `registration_performed`,
`setup_performed`, `tasks_performed`, and `service_started` as explicit false.
No public operation invokes it yet.
The source-available `manager-tasks` slice validates PLAN
`inspect`/`quiesce`/`resume`/`validate` actions on one Ubuntu 24.04 manager
stable ID after current successful `base-os` and `manager-server` evidence.
Official Manager 3.12 `sctool` task, suspend, resume, backup, and repair
commands require a running API and a registered cluster; this slice never
starts Manager, writes tokens, registers a cluster, or invokes those
commands. Check mode reports `not-predicted`. Strict
`deploy-scylla-vms.ansible-manager-tasks/v1` results keep `applied=false`
and report backup/repair work as not-performed with exact inactive,
unregistered, and backend blockers. No public operation invokes it yet.
The source-available `monitoring-agent` slice installs the exact ScyllaDB
2026.2 `scylla-node-exporter` package on one Ubuntu 24.04 Scylla stable ID
after current successful `base-os` and `scylla-install` evidence. It reuses
the authenticated 2026 signing key and official Ubuntu Scylla 2026.2
repository, leaves `scylla-node-exporter` disabled/inactive, and does not
bind port 9100, write exporter configuration, install process-exporter or the
monitoring stack, generate target files, register Manager, or start Scylla.
Check mode reports `not-predicted`. Strict
`deploy-scylla-vms.ansible-monitoring-agent/v1` results keep listen policy as
`not-started` and stack/targets/process-exporter/registration/startup as
explicit false. No public operation invokes it yet.
The source-available `monitoring-stack` slice places the exact official
Scylla Monitoring 4.16.0 archive on one Ubuntu 24.04 monitoring stable ID
after current successful `base-os` evidence. It digest-checks the tagged
GitHub archive, verifies the official `versions.sh` Prometheus/Grafana/
Alertmanager/Loki/Promtail pins and 2026.2 dashboard support, and does not
install Docker, pull images, start containers, generate Compose, Grafana
auth, or scrape targets, bind ports 3000/9090/9093, register Manager, or
start Scylla. Check mode reports `not-predicted`. Strict
`deploy-scylla-vms.ansible-monitoring-stack/v1` results keep listen policy as
`not-started` and targets/auth/public-bind/Compose/containers/registration/
startup/secrets as explicit false. No public operation invokes it yet.
The source-available `monitoring-targets` slice writes official Scylla
Monitoring 4.16.0 Prometheus target files on one Ubuntu 24.04 monitoring
stable ID after current successful `base-os` and `monitoring-stack` evidence.
It generates `scylla_servers.yml` from RFC 1918 Scylla inventory identities,
the required Manager `host:5090` file, and the official node_exporter and
manager-agent reuse files. It does not start Docker, Prometheus, Grafana,
Alertmanager, or node_exporter, bind UI ports, install the stack or agents,
register Manager, or start Scylla. Check mode reports `not-predicted`. Strict
`deploy-scylla-vms.ansible-monitoring-targets/v1` results omit addresses and
file contents, keep listen policy as `not-started`, and keep scrape-readiness
as `not-performed`. No public operation invokes it yet.
This code has not been exercised on real devices or jump hosts, and no CLI
operation can invoke it; live use remains gated by future operation
orchestration and rediscovery.
The other 10 operations return a stable "not implemented" refusal. No CLI
operation writes canonical state or invokes Terraform, OCI, or an infrastructure
mutation.

Version: `26.9.1`

## Table of contents

- [Intended capabilities](#intended-capabilities)
- [Planned stack](#planned-stack)
- [Configuration and safety principles](#configuration-and-safety-principles)
- [Foundation usage](#foundation-usage)
- [TOML configuration examples](#toml-configuration-examples)
- [Repository contents](#repository-contents)
- [Limitations](#limitations)
- [Documentation to consult during implementation](#documentation-to-consult-during-implementation)

## Intended capabilities

The design in `PLAN.md` covers:

- an extensible operation model with `deploy`, `add-node`, `replace-node`,
  `destroy-node`, `destroy`, `scale-out`, `scale-in`, `redeploy`,
  `refresh-monitoring`, `upgrade-os`, `check-jump-hosts`, and a read-only,
  provenance-aware `show`;
- OCI as the only initially accepted cloud provider, with provider boundaries
  designed to permit future AWS or GCP implementations;
- explicit cluster names, zones, per-zone ScyllaDB node counts, zero or more
  jump hosts, and separate instance types for ScyllaDB, Manager, monitoring, and
  jump-host roles;
- Terraform-managed compute, VCN/networking, security controls, storage, and
  per-cluster state;
- Ansible-managed OS prerequisites, ScyllaDB, ScyllaDB Manager, monitoring,
  topology changes, and rolling maintenance;
- inventory generated and validated from Terraform JSON output;
- stable logical node identities that do not depend on list positions or IP
  addresses; and
- dry-run/plan/confirmation safeguards, locking, drift refusal, redacted logs,
  idempotence, resumability, and layered tests.

Manager and monitoring are separate hosts by default in the plan. Uneven and odd
node distributions can be represented through repeatable `ZONE=COUNT` mappings,
but policy validation must warn or refuse topologies that do not meet explicitly
selected replication and failure-domain goals.

## Planned stack

- Python 3.11 or newer, with a standard-library `argparse` CLI and
  [`platformdirs`](https://platformdirs.readthedocs.io/) for the canonical
  per-user state root. Ruff, mypy, and pytest are the established formatter/
  linter, type checker, and test runner.
- [Terraform](https://developer.hashicorp.com/terraform) and the
  [OCI provider](https://registry.terraform.io/providers/oracle/oci/latest/docs)
  for infrastructure. The packaged root supports stable Terraform
  `>=1.5.0,<2.0.0`, constrains OCI to `~>9.1.0`, and tracks the generated
  provider lock file.
- [Ansible](https://docs.ansible.com/) for host configuration and orchestration.
  The internal boundary supports stable ansible-core `>=2.17.0,<2.21.0`;
  Python 3.14 development environments require ansible-core 2.20+. Development
  checks use ansible-lint `>=25,<27` and yamllint `>=1.35,<2`.
- ScyllaDB's
  [Ansible integration guide](https://docs.scylladb.com/manual/stable/using-scylla/integrations/integration-ansible.html)
  and [upstream roles](https://github.com/scylladb/scylla-ansible-roles) as
  implementation inputs.

The upstream roles
[wiki](https://github.com/scylladb/scylla-ansible-roles/wiki) is useful context,
but wiki content may be stale. Future implementation must validate it against
current role source, release tags, and official ScyllaDB documentation.

## Configuration and safety principles

- Secret values will be read only from environment variables. Secret
  command-line flags, plaintext secret config values, and persistent credential
  files created by the tool are out of scope.
- For the state root, the planned precedence is exactly `--state-dir` over
  `DEPLOY_SCYLLA_VMS_STATE_DIR` over
  `platformdirs.user_state_path("deploy-scylla-vms", appauthor=False)`.
- Cluster names will be strictly validated rather than silently sanitized. The
  canonical cluster root is
  `<state-dir>/clusters/<validated-cluster-name>/`.
- Terraform working data, local state, and saved plans will live under
  `<cluster-root>/terraform/`; generated Ansible inventory will live under
  `<cluster-root>/ansible/`; locks, operation journals, and logs will remain
  under that same external cluster root.
- Every Terraform command will use an explicit per-cluster working directory,
  `TF_DATA_DIR`, backend state path, and plan path as applicable. It will never
  rely on the repository source tree or caller's current directory for runtime
  state.
- The internal Terraform boundary accepts stable Terraform CLI releases
  `>=1.5.0,<2.0.0`. It discovers executables only through explicit paths, parses
  `terraform version -json`, starts from a minimal allowlisted environment, and
  constructs only version/init/fmt-check/validate/plan/show/output commands.
  These APIs are not connected to a deploy CLI workflow.
- After an external planning owner has created the canonical saved plan and
  obtained bounded `terraform show -json` output, the internal
  `deploy-scylla-vms.terraform-plan-checkpoint/v1` service can persist one
  immutable, operation-lock-bound metadata companion beside that plan. The
  companion and `deploy-scylla-vms.terraform-plan-review/v1` projection retain
  no plan values, resource addresses, state contents, lineage, or paths. They
  bind those protected artifacts by digest, classify destructive/replacement
  scope and refresh drift, and fail closed if current state, desired inputs,
  staged source, toolchain, plan bytes/JSON, or journal evidence changes. This
  is a review checkpoint only; it cannot authorize or execute apply.
- The internal `compose_deploy_plan_journal` API loads that checkpoint only from
  its canonical operation path and appends exactly one existing-v1
  `PLAN/validated` journal event whose digest is the checkpoint digest and whose
  summary code is `terraform-plan-reviewed`. The checkpoint exists first; a
  failed journal write leaves a recoverable checkpoint-only prefix, and exact
  re-entry reuses generation 2 without another write. The independently
  versioned
  `deploy-scylla-vms.terraform-deploy-plan-composition-report/v1` projection
  contains only schemas/digests, bounded counts/classes/booleans/scope digests,
  and explicit uncollected/unavailable execution state. Common journal v1
  remains schema-compatible and stores no plan values, addresses, commands, or
  paths. This API neither approves the plan nor authorizes or executes apply.
- The internal `orchestrate_deploy_plan` API composes the reviewed controlled
  runner, command builder, checkpoint creator, and journal composer under one
  already-held deploy lock. It accepts no caller path, command, arguments,
  variables, environment, or plan JSON. Fresh work runs only an exact detailed
  plan to `<operation-uuid>.tfplan.staging`, validates bounded strict show JSON,
  atomically publishes `<operation-uuid>.tfplan`, then creates the immutable
  checkpoint before journal composition. An exact saved-plan-only prefix may
  rerun show after unchanged-input checks; an exact checkpoint prefix and
  generation-2 composed PLAN state make no Terraform call. Staging ambiguity,
  path/link/permission/size conflicts, drift, toolchain mismatch, and uncertain
  process results fail closed without deleting or automatically replanning.
  Its redacted
  `deploy-scylla-vms.terraform-deploy-plan-orchestration-report/v1` contains
  only stage states, schemas/digests, bounded classifications/counts/booleans,
  toolchain version, and retry/recovery truth. No CLI invokes it.
- The internal `authorize_deploy_apply` API accepts only canonical cluster
  identity, one operation UUID, the matching held deploy lock, and a normalized
  typed proof. It revalidates the exact journal/checkpoint/review/saved-plan plus
  desired/tfvars/source/backend/state/toolchain bindings before writing the
  owner-only immutable authorization companion under `terraform/plans/`.
  No-change plans remain authorization-free. Create/update plans require
  ordinary interactive or `--yes` approval; destructive plan scope requires a
  separate `--allow-destructive` fact and exact address-free counts/digests.
  Review-required refresh drift needs separate interactive review; conflict
  drift is refused. The v1 journal remains unchanged at PLAN, and the report
  keeps apply command and execution unavailable.
- The internal `safeguard_deploy_apply_state` API accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching held deploy
  lock. Apply-required plans must have the exact current unconsumed
  authorization. Existing local state is read with bounded descriptor-relative
  no-follow checks, matched to the reviewed lineage/serial/full digest, and
  copied byte-for-byte to immutable owner-only `terraform/backups/` storage.
  Drift-free create-only plans may instead persist an explicit verified-absent
  checkpoint without a state file or backup. The independently versioned
  safeguard record and redacted report bind all reviewed plan, authorization,
  desired, source, backend, state, and toolchain facts. Exact record/backup
  re-entry and a backup-only prefix are recoverable; all conflicting artifacts
  fail closed. It neither consumes authorization nor constructs or executes
  apply, and no CLI invokes it.
- The offline OCI adapter consumes caller-supplied validated image, zone, shape,
  and local-NVMe capability facts; it performs no account lookup and does not
  claim that resources or capacity exist. Its strict deterministic tfvars model
  includes only non-secret desired/provider inputs and validated public SSH key
  material.
- Matching-lock internal APIs can persist generated
  `cluster.auto.tfvars.json` and atomically stage an approved, hash-manifested
  source bundle under the canonical Terraform work directory. They reject
  tamper, unexpected files, downgrade, unsafe links, and source changes once
  Terraform state/backend/provider data is active. No CLI invokes them.
- The package has one active OCI Terraform root at the stable physical path
  `scylla_vms/terraform/bundles/oci_root/`. Logical immutable identifiers such
  as `oci-root/v3` are stored in source records and bind exact file hashes; they
  are not parallel package-directory names. During unreleased development the
  stable source evolves and its logical ID advances when compatibility requires
  it. An old physical root is retained only if a future migration genuinely
  requires parallel packaged source.
- Terraform state is sensitive and must be protected with restrictive access,
  locking, encryption/versioning where available, and explicit backend policy.
- The internal inventory service deterministically projects validated Terraform
  manifests into JSON-compatible static inventory at the canonical
  `ansible/inventory.yml` path. It records the source manifest generation/digest
  and requires explicit write approval; no CLI invokes this write API.
  Direct OpenSSH discovery creates untrusted candidates only. Matching-lock
  internal APIs can explicitly confirm and persist approved Ed25519 or NIST
  P-256 ECDSA host keys in `ansible/trust.json`, with deterministic derived
  `known_hosts` and `ssh_config`. Trust is bound to exact observation/inventory
  generations, digests, stable host/provider identities, endpoints, and routes.
  The internal routed candidate collector can now scan only canonical RFC 1918
  private inventory hosts assigned to one already trusted jump stable ID. Its
  exact-one-jump `routed-keyscan` support playbook invokes only
  `/usr/bin/ssh-keyscan` with fixed port, algorithms, timeout, locale, argument
  array, and output bounds. Endpoint-bearing input is `no_log`; the result is
  an address-free, in-memory candidate projection bound to current observation,
  inventory, trust, readiness, provider/stable identities, and route digests.
  This one playbook overrides Ansible's persistent log path with `/dev/null` so
  candidate keys remain in process memory only. It never grants or persists
  trust, and existing or changed trust remains blocked for the separate
  replacement workflow.
- Private cluster hosts will not be exposed publicly by default. Zero-jump-host
  deployments require another verified private route; jump-host deployments
  require deterministic SSH routing and host-key verification.
- The internal Ansible service parses exact `ansible-inventory --list` and
  `--graph` output, rejects unknown hosts/groups, changed hostvars/routes,
  aliases, and secret-like keys, and produces an immutable readiness report.
  Production execution requires a current report with complete trust and valid
  routing. `check-jump-hosts` invokes only the two guarded connectivity sources;
  no CLI invokes evidence persistence.
- The internal operation-initiation owner accepts only canonical cluster
  identity, one typed UUID, exact `check-jump-hosts`, its bounded typed request,
  and the caller's already-acquired matching `ClusterLock`. Lock acquisition is
  unchanged: `ClusterLock` first flocks the canonical cluster directory and
  then its canonical lock file; initiation acquires no nested lock. It requires
  the fully initialized layout and current schema-v2 metadata/desired identity,
  refuses another pending/in-progress/interrupted operation, and scans
  persisted sibling cluster histories for UUID replay. Its one atomic write is
  generation 1 of the existing `deploy-scylla-vms.operation/v1` schema at
  `<cluster-root>/operations/<operation-uuid>.json`, with
  `in-progress`/`plan`, exact operation/cluster identity, the normalized request
  digest, null resume digest, and empty evidence. Empty evidence means planning
  has not yet happened; preparation may make the sole same-phase transition to
  generation 2 by appending exactly one resolved PLAN checkpoint before any
  companion. Only byte-identical untouched initiation state is reusable.
  Failure before atomic publication leaves no journal; no later failure causes
  automatic rollback or deletion. No CLI invokes this API.
- The internal operation-binding store writes only
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-binding.json`
  as strict owner-only atomic
  `deploy-scylla-vms.ansible-operation-binding/v1`. The matching operation lock
  must already be held. The record is independently versioned from
  `deploy-scylla-vms.operation/v1`; it is immutable, generation/digest guarded,
  and records only allowlisted identities, classifications, stable target IDs,
  schemas, states, generations, and digests. The internal operation-context
  store then writes only
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-context.json`
  as immutable `deploy-scylla-vms.ansible-operation-context/v1`. Its explicit
  `check-jump-hosts/v1` value schema allows only jump stable IDs, destination
  and depth enums, role/port destination checks, and bounded numeric timeouts.
  The record repeats the exact binding/request/plan/classification/target
  digests and identities plus a digest of those safe values; it stores no
  addresses, probes, commands, environments, paths, arbitrary variables, or
  secrets. Creation order is common PLAN journal, binding, context, optional
  authorization, then execution. Binding v1 remains unchanged and acyclic:
  context points to its exact digest, and later reconstruction must reproduce
  the request and bound plan digests. A missing legacy context fails closed.
  The separate authorization store
  writes only
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-authorization.json`
  as strict `deploy-scylla-vms.ansible-operation-authorization/v1`, under the
  same matching operation lock and exact ready PLAN journal checkpoint. It
  records only normalized proof kinds/sources and digests, keeping ordinary,
  destructive-class, exact-scope, wipe, and monitoring-restart proof separate.
  Offline `deploy-scylla-vms.ansible-operation-resume-validation/v2` re-resolves
  the request and Ansible plan and requires that authorization unchanged for
  non-read-only work while requiring its absence for read-only work and refuses
  once an execution companion exists. The internal
  `deploy-scylla-vms.ansible-operation-preparation-report/v1` coordinator
  deterministically calls these existing stores in binding/context/
  authorization order, reuses an exact immutable prefix, and preserves a valid
  partial prefix after a later write failure. It accepts no caller plan,
  commands, variable map, environment, inventory, or runtime paths and creates
  no execution record. Only modeled `check-jump-hosts` can currently prepare;
  all other kinds are blocked before writes. The internal execution store writes only
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-execution.json`
  as strict `deploy-scylla-vms.ansible-operation-execution/v1`. Under the same
  already-held operation lock, it records started intent before at most one
  executor call, binds each step's catalog/source/command/limit/variable
  evidence through the catalog/source/command/variables digests and exact
  stable-ID limit, and retains only strict result digests and bounded outcome
  states. The production-capable internal executor accepts only that immutable
  step and an exact typed current-state context, revalidates the matching
  operation lock, rendered config/inventory/trust, readiness, packaged source,
  catalog and playbook hash, rebuilds the anchored command through the existing
  builder, and calls the existing controlled service/runner exactly once.
  Result mapping uses the established strict per-playbook parsers and treats
  blocked or otherwise non-success evidence as failure even when Ansible exits
  zero. For the two modeled `check-jump-hosts` steps, the adapter then writes
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-evidence.json`
  as strict `deploy-scylla-vms.ansible-operation-evidence/v1`. Entries append in
  step order and retain only exact preflight parity/counts/digests or stable-ID
  connectivity and requested role/port outcomes. The receipt's
  `evidence_digest` is the persisted semantic projection digest, and the
  handoff re-reads that exact entry before recording `succeeded`.
  It never stores commands, variable values, output, addresses, inventory,
  routes, keys, environment, trust material, or protected paths. The common v1
  journal stays byte-for-byte at its PLAN checkpoint. The internal coordinator loads those
  canonical artifacts without rendering or overwriting them, validates and
  reconstructs the operation context before tool probing, validates
  machine-inventory parity before the durable `started` write, then invokes this
  handoff once and returns only
  `deploy-scylla-vms.ansible-operation-coordinator-report/v1`. The current
  reconstruction boundary supports the bounded allowlisted read-only
  `check-jump-hosts` request forms; all other operation kinds remain explicitly
  unmodeled. The internal `check-jump-hosts` orchestrator consumes only that
  prepared context and canonical execution state, invokes this coordinator in
  exact next-step order, and reports `semantic-evidence-ready` after both
  receipts and projections verify. A legacy complete execution without the
  companion remains `post-verification-pending`; no raw-output migration is
  attempted. No CLI invokes this orchestrator, coordinator, handoff, or adapter.
- `evidence-collect` uses explicit stable-ID limits, serial batches of five, and
  read-only check-mode-safe modules. It projects only host identity/role,
  OS/kernel/time/uptime, CPU/memory, approved-mount usage, redacted block-device
  shape, allowlisted role service state/version, and bounded Scylla health
  status. Missing facts, services, commands, or hosts remain partial,
  unavailable, or not performed; raw Ansible output is never persisted.
- Destructive and rolling operations will require current reconciliation,
  health gates, exact stable target IDs, backup-policy reporting where
  applicable, and explicit confirmation.

The CLI/environment/TOML contract and local request validation described above
are implemented and non-mutating. TOML is non-secret, schema-versioned, strict
about fields and native types, and lower precedence than environment and CLI
values. Protected values are accepted only through documented environment
names, held behind redacted typed wrappers, and never persisted or forwarded.
Explicit internal APIs can initialize the canonical layout, acquire a cluster
lock, and persist desired-cluster/journal schemas; parsing and unimplemented
operations never call them. Internal matching-lock APIs can also persist strict
`deploy-scylla-vms.observed/v1`, `deploy-scylla-vms.inventory/v1`, and
independently versioned Ansible request/plan binding records. They do not
refresh from Terraform or run Ansible.

The narrow internal `finalize_prepared_check_jump_hosts` API accepts only
canonical state-root/cluster identity, an operation UUID, and its matching
already-held operation lock. It revalidates binding, context, terminal
execution, semantic evidence, journal, current observation/inventory/trust,
reconstructed readiness, source, and catalog state. Its immutable companion and
returned `deploy-scylla-vms.ansible-operation-finalization-report/v1` expose
only address-free allowlisted stable-ID and role/port result facts, bounded
statuses/counts, and provenance digests. No CLI invokes this finalizer.

The narrow internal `coordinate_check_jump_hosts_lifecycle` API composes
checkpoint preparation, deterministic orchestration, semantic-evidence
validation, and finalization under the matching held operation lock. It does
not create the common journal: callers must provide an existing exact
`IN_PROGRESS/PLAN` journal produced by the internal initiation owner. Its strict
redacted lifecycle report exposes bounded stage outcomes, counts, journal
status/phase, retry/recovery truth, schemas, and digests. It accepts no caller
plan, step, path, command, variable map, environment, evidence, or finalization
data, has no CLI wiring, and cannot alter the public no-write workflow.

The narrow internal `coordinate_check_jump_hosts_operation` API is the sole
one-call composition of initiation plus that lifecycle. Its caller must already
hold the exact `check-jump-hosts` `ClusterLock`, acquired in the existing
cluster-directory-then-lock-file order; the API neither acquires nor nests a
lock. It accepts only canonical cluster identity, one UUID, the bounded typed
request, and controlled runner/executable dependencies. It calls initiation for
a missing or exact untouched generation-1 journal, calls lifecycle under the
same protected scope, and treats later exact prefixes as already initiated
because the initiation owner intentionally refuses advanced history. Component
errors remain typed application errors for the established CLI-boundary
mapping.

The current race-resistant initializer and application lock use POSIX
`dir_fd`/`O_NOFOLLOW` and `flock` facilities. The state root's direct parent
must already exist; initialization creates only the selected root and its
canonical children. A validated fallback directory initializer exists for
platforms without the POSIX directory APIs, but application locking currently
fails closed where `flock`/`O_NOFOLLOW` are unavailable.

`.gitignore` does not configure Terraform state placement. Its broad
`.terraform/`, `*.tfstate`, plan, and crash patterns are defense-in-depth against
accidental generated files anywhere in the checkout. `.terraform/` is
Terraform's provider/module/backend working cache, not the state directory.
`.terraform.lock.hcl` remains trackable for reproducible provider selections.

## Foundation usage

The implemented root CLI can display help and version information:

```console
$ python deploy_scylla_vms.py --help
$ python deploy_scylla_vms.py --version
$ deploy-scylla-vms --help
```

Global flags use the planned global-before-subcommand order; operation flags
follow the subcommand. Given an existing owner-only canonical state root with a
valid schema-v2 `cluster.json`, this reads persisted desired state and emits the
stable `deploy-scylla-vms.show/v1` JSON report:

```console
$ python deploy_scylla_vms.py \
    --cluster-name example \
    --state-dir /operator-selected/per-user-state-root \
    --json \
    show \
    --section summary
```

The default local report requires no credentials or network access. It validates
the state root, cluster identity, schema, generation, digests, permissions, and
unexpected local Terraform-state locations under an exclusive read lock. The
lock uses the canonical cluster directory and never creates or rewrites a lock
file; shared/read locking is deferred. Desired identity, topology, stable logical
IDs, shapes, network/storage policy, provenance, and validated latest
operation-journal summary are projected through explicit output allowlists. If
internal APIs previously persisted a validated Terraform observation and
inventory, `show` also reports their local timestamps/digests,
provider/resource/storage/routing summaries, reconciliation findings, inventory
freshness, and unresolved host-trust readiness. Persisted evidence is never
presented as provider-live evidence. SSH public-key paths, customer-managed key
IDs, protected environment values, and exact addresses are not rendered by
default.

Missing Terraform output/inventory and all provider, connectivity, and
live-health sources are labeled `unavailable`, `not-performed`, or `unknown`;
the report never calls them or claims health. `--include-addresses` reveals exact
addresses only from a validated persisted observation or inventory; inventory-
only addresses are marked stale because their source manifest is unavailable.
Otherwise the address list remains unavailable. Any `--live` value exits `10`
explicitly without performing the check. The `--fail-on` values `drift`,
`conflict`, and `unknown` evaluate the available local findings, while
unavailable external evidence remains unknown.
Unknown `--node-id` values are errors, while an omitted node filter means all
persisted logical hosts. Section and host rows are deterministic.

Given complete current observation, inventory, trust, `known_hosts`, SSH route,
and staged Ansible configuration evidence, this performs a bounded check of one
validated jump host and emits `deploy-scylla-vms.check-jump-hosts/v2` JSON:

```console
$ deploy-scylla-vms \
    --cluster-name example \
    --state-dir /operator-selected/per-user-state-root \
    --json \
    check-jump-hosts \
    --jump-host jump-host-1 \
    --depth route \
    --destination scylla \
    --destination-check scylla=9042 \
    --connect-timeout-seconds 10 \
    --check-timeout-seconds 300
```

The check acquires the non-mutating cluster read lock, validates all local
provenance and routes, runs `inventory-preflight`, then runs
`connectivity-check` with an exact stable-ID limit. The connectivity playbook
preserves its SSH ping and uses read-only `ansible.builtin.wait_for` from each
selected jump for resolved private destination pairs. Host-key checking remains
enabled. Human and JSON output omit addresses, key material, private-key paths,
credentials, and raw Ansible output. Partial, full, malformed-evidence, and
timeout results return exit `7` after rendering the redacted report.

`--destination-check` accepts only `ROLE=PORT`: Scylla ports `7000`, `7001`,
`9042`, or `9142`; Manager port `5080`; and monitoring ports `3000` or `9090`.
Targets are never user-supplied addresses or names: validated inventory resolves
them to RFC 1918 private hosts assigned to the selected jump. `--depth route`
selects the first stable logical target per requested role and jump;
`--depth all-targets` selects every bounded assigned target. `--depth bastion`
cannot be combined with a destination probe, and `all-targets` without an
explicit TCP check remains an exit-`10` refusal because private-target SSH
checking is not implemented.

The deploy parser exposes the documented operation-specific contract. This
deliberately incomplete example demonstrates its shape and exits `2` because
required OCI, shape, SSH, and storage inputs are omitted:

```console
$ python deploy_scylla_vms.py \
    --cloud-provider oci \
    --cluster-name example \
    --state-dir /operator-selected/per-user-state-root \
    deploy \
    --zone AD-1 \
    --zone AD-2 \
    --nodes-per-zone AD-1=3 \
    --nodes-per-zone AD-2=3 \
    --jump-host-count 1 \
    --plan
```

See `PLAN.md` and `deploy-scylla-vms deploy --help` for the normative
per-operation contract. Parsing a complete non-`show` request still exits `10`;
no operation executes infrastructure or creates application state.
`--config`/`DEPLOY_SCYLLA_VMS_CONFIG` selects an absolute, canonical non-secret
TOML file with `schema_version = "deploy-scylla-vms.config/v2"` and one
`[cluster]` table. Keys use the documented underscore field names. CLI values
override environment values, which override TOML values, which override built-in
defaults; `state_dir`, credentials, actions, selectors, and confirmations are
never accepted from TOML.

## TOML configuration examples

The config document has exactly two top-level entries: the schema marker and one
`[cluster]` table. Field names use underscores and values use native TOML types;
for example, counts are integers, zones and CIDRs are arrays, and zone/role maps
are inline tables. Strings are not coerced into other types.

### Minimal block-volume cluster

This single-zone example contains the values currently needed to compile a new
OCI `ClusterSpec`. `cloud_provider = "oci"`, `network_mode = "create"`, and
`jump_host_count = 0` are optional defaults shown for clarity. `ssh_user` may
instead be derived by a future provider/image adapter, but specifying it keeps
the local desired-state compilation complete. Manager and monitoring each
default to one separate host, with placement derived from the declared zones.
The data-volume retention values are optional defaults made explicit so their
intended lifecycle policy is visible.

<!-- config-example:minimal:start -->
```toml
schema_version = "deploy-scylla-vms.config/v2"

[cluster]
cloud_provider = "oci"
cluster_name = "example-minimal"
oci_region = "us-ashburn-1"
oci_compartment_id = "ocid1.compartment.oc1..exampleminimal"
scylla_image_operating_system = "Ubuntu"
scylla_image_operating_system_version = "24.04"
manager_image_operating_system = "Ubuntu"
manager_image_operating_system_version = "24.04"
monitoring_image_operating_system = "Ubuntu"
monitoring_image_operating_system_version = "24.04"

zone = ["AD-1"]
nodes_per_zone = { "AD-1" = 3 }
jump_host_count = 0

scylla_instance_type = "VM.Standard.E5.Flex"
manager_instance_type = "VM.Standard.E5.Flex"
monitoring_instance_type = "VM.Standard.E5.Flex"

network_mode = "create"
oci_vcn_cidr = "10.20.0.0/16"
oci_private_subnet_cidr = { "AD-1" = "10.20.1.0/24" }
ssh_user = "ubuntu"
ssh_public_key_path = "/opt/deploy-scylla-vms/example-bootstrap.pub"

scylla_storage_backend = "block-volume"
scylla_block_volume_count = 1
scylla_block_volume_size_gib = 500
scylla_block_volume_vpus_per_gb = 10
scylla_block_volume_attachment_type = "paravirtualized"
scylla_block_volume_retention = "delete"

manager_data_volume_size_gib = 100
manager_data_volume_vpus_per_gb = 10
manager_data_volume_attachment_type = "paravirtualized"
manager_data_volume_retention = "retain"

monitoring_data_volume_size_gib = 200
monitoring_data_volume_vpus_per_gb = 10
monitoring_data_volume_attachment_type = "paravirtualized"
monitoring_data_volume_retention = "retain"
```
<!-- config-example:minimal:end -->

A one-device Scylla policy derives the `single` layout. In-transit encryption
defaults to `disabled`; CHAP is also disabled and enabling it is currently
refused. Manager and monitoring application storage is always one Block Volume
in the current model. The example OCID and public-key path are deliberately
fake; the referenced public-key file must exist and be readable when the deploy
request is parsed.

### Multi-zone auto-storage cluster

This more complete example uses an existing VCN, maps every deployed role to a
subnet, assigns explicit Manager/monitoring zones, and requests two jump hosts.
All configured zones have both node-count and unique Scylla rack entries.
Scylla `auto` storage requires both local-NVMe adequacy minimums and a complete
Block Volume fallback. Because both paths use two devices, `raid0` is the
required layout. These settings express desired policy; the offline adapter can
select from explicitly supplied capability facts, but it performs no tenancy
lookup or capacity check.

<!-- config-example:complete:start -->
```toml
schema_version = "deploy-scylla-vms.config/v2"

[cluster]
cloud_provider = "oci"
cluster_name = "example-multizone"
oci_region = "us-ashburn-1"
oci_compartment_id = "ocid1.compartment.oc1..examplemultizone"
scylla_image_operating_system = "Ubuntu"
scylla_image_operating_system_version = "24.04"
manager_image_operating_system = "Ubuntu"
manager_image_operating_system_version = "24.04"
monitoring_image_operating_system = "Ubuntu"
monitoring_image_operating_system_version = "24.04"
jump_host_image_operating_system = "Ubuntu"
jump_host_image_operating_system_version = "24.04"

zone = ["AD-1", "AD-2", "AD-3"]
nodes_per_zone = { "AD-1" = 2, "AD-2" = 2, "AD-3" = 1 }
scylla_datacenter = "example-dc"
scylla_rack = { "AD-1" = "rack-a", "AD-2" = "rack-b", "AD-3" = "rack-c" }

manager_count = 1
manager_zone = "AD-1"
monitoring_count = 1
monitoring_zone = "AD-2"
jump_host_count = 2

scylla_instance_type = "BM.DenseIO.E5.128"
manager_instance_type = "VM.Standard.E5.Flex"
monitoring_instance_type = "VM.Standard.E5.Flex"
jump_host_instance_type = "VM.Standard.E5.Flex"

network_mode = "existing"
oci_vcn_id = "ocid1.vcn.oc1..examplevcn"
oci_subnet = { scylla = "ocid1.subnet.oc1..examplescylla", manager = "ocid1.subnet.oc1..examplemanager", monitoring = "ocid1.subnet.oc1..examplemonitoring", jump-host = "ocid1.subnet.oc1..examplejump" }
operator_cidr = ["198.51.100.0/24", "2001:db8:100::/56"]
ssh_user = "ubuntu"
ssh_public_key_path = "/opt/deploy-scylla-vms/example-bootstrap.pub"

scylla_storage_backend = "auto"
scylla_storage_min_device_count = 2
scylla_storage_min_total_gib = 1000
scylla_storage_layout = "raid0"
scylla_block_volume_count = 2
scylla_block_volume_size_gib = 500
scylla_block_volume_vpus_per_gb = 20
scylla_block_volume_attachment_type = "paravirtualized"
scylla_block_volume_retention = "delete"
scylla_block_volume_in_transit_encryption = "enabled"

manager_data_volume_size_gib = 100
manager_data_volume_vpus_per_gb = 10
manager_data_volume_attachment_type = "paravirtualized"
manager_data_volume_retention = "retain"
manager_data_volume_in_transit_encryption = "enabled"

monitoring_data_volume_size_gib = 250
monitoring_data_volume_vpus_per_gb = 10
monitoring_data_volume_attachment_type = "paravirtualized"
monitoring_data_volume_retention = "retain"
monitoring_data_volume_in_transit_encryption = "enabled"
```
<!-- config-example:complete:end -->

`oci_subnet` role keys are exactly `scylla`, `manager`, `monitoring`, and
`jump-host`. Existing-network mode requires the VCN and one subnet for every
role whose host count is nonzero; create mode forbids those existing-resource
selectors. CIDRs must use canonical network spelling. Jump hosts are assigned
stable logical IDs and distributed in round-robin order over sorted canonical
zones when the desired specification is compiled.

Config schema v2 requires explicit per-deployed-role OCI platform-image
operating-system and version filters. The offline adapter accepts only AVAILABLE candidates
compatible with the selected shape architecture, chooses the unique newest
creation time, and refuses no-match or tied-newest results. This is deterministic
selection evidence, not proof of image availability, tenancy capacity, or
ScyllaDB support. Prefix matching must be explicitly requested; no OS/version
default is inferred. Caller-supplied persisted image evidence pins existing
logical hosts, while newly selected IDs/names/creation times are embedded in the
generated tfvars record so a future saved plan can remain immutable.

Managed networks require an explicit RFC 1918 IPv4 VCN CIDR and one
non-overlapping private subnet CIDR per zone. Public subnet CIDRs and public IPs
are allowed only for explicitly enabled jump hosts with operator ingress CIDRs;
Scylla, Manager, and monitoring hosts remain private.

### Selecting and protecting the config

`--config` is a global option and therefore precedes the subcommand:

```console
$ python deploy_scylla_vms.py \
    --config /opt/deploy-scylla-vms/cluster.toml \
    deploy \
    --dry-run \
    --oci-auth-mode instance-principal
```

The equivalent config-path environment variable is
`DEPLOY_SCYLLA_VMS_CONFIG`:

```console
$ DEPLOY_SCYLLA_VMS_CONFIG=/opt/deploy-scylla-vms/cluster.toml \
    python deploy_scylla_vms.py \
    deploy \
    --dry-run \
    --oci-auth-mode instance-principal
```

Both commands currently load, parse, and locally validate inputs, then exit `10`
because the deploy workflow is not implemented. They create no application
state and make no OCI, Terraform, or Ansible call. Complete `ClusterSpec`
compilation is currently an internal API that additionally requires canonical
zone identities from the future provider boundary.

For a new cluster, non-secret values resolve as CLI over environment over config
over built-in default. The state root is the narrower exception:
`--state-dir` over `DEPLOY_SCYLLA_VMS_STATE_DIR` over the platform default, with
no config-file field. For an existing cluster, persisted desired state is the
authoritative baseline; differing CLI, environment, or config values become
identity conflicts or explicit proposed changes and never silently rewrite it.

The selected config path must be absolute and canonical. The loader accepts
only a regular, singly linked file and rejects symlink components and hard
links. On POSIX it requires current-user ownership and refuses group/other
write bits; mode `0600` is recommended, while read-only group/other bits are not
currently rejected. Config files are non-secret: credentials, private keys,
passwords, tokens, action/confirmation fields, interpolation, include
directives, and secret-like keys are rejected. Required secrets remain
environment-only.

## Repository contents

- `PLAN.md` — comprehensive implementation plan, operation workflows,
  architecture, safety model, testing strategy, milestones, and references.
- `AGENTS.md` — coding, test, documentation, infrastructure, Ansible, security,
  versioning, and contribution rules for future agents.
- `UPSTREAM_TODO.md` — evidence-backed tracker for local workarounds to verified
  upstream ScyllaDB Ansible role gaps and future fix adoption.
- `.gitignore` — defense-in-depth exclusions for accidental Python, Terraform,
  Ansible, secret, test, editor, and OS runtime artifacts; it does not select the
  application state location.
- `LICENSE` — MIT License.
- `README.md` — current project overview and status.
- `VERSION` — current project version.
- `RELEASE_NOTES.md` — release-level documentation history.
- `deploy_scylla_vms.py` — thin source-tree CLI entry point.
- `scylla_vms/` — typed CLI/environment contracts, immutable request models,
  local validation, protected-input handling, canonical state initialization,
  locking, atomic persistence, strict journal, error, and redaction foundation.
- `tests/` — local unit tests; they use temporary paths and no network or cloud
  infrastructure.
- `pyproject.toml` — package metadata, Python support, console entry point, and
  Ruff/mypy/pytest configuration.

Run the authoritative fake-only suite with external Ansible and Terraform
discovery excluded from `PATH`:

```console
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PATH="/usr/bin:/bin" .venv/bin/python -m pytest -q
```

The explicit virtual-environment interpreter keeps the Python test dependencies
available while the controlled `PATH` excludes Homebrew and virtual-environment
tool installations. Optional localhost Ansible checks then skip; the configured
`real_device` marker remains deselected. Run tool-backed Ansible and Terraform
checks separately when those integrations are intentionally under test.

## Limitations

- No public mutating operation workflow or provider API client has been implemented.
  The internal Ansible runner boundary and complete metadata registry include
  production `inventory-preflight`, `connectivity-check`, `evidence-collect`,
  narrowly scoped `base-os`, and read-only Scylla `storage-discover` and
  `storage-preflight`, destructive internal `storage-prepare`, and read-only
  `storage-postcheck`, destructive internal `storage-retire`, `scylla-install`,
  and `scylla-configure` playbooks, while
  the exact single-target `scylla-bootstrap` first-start/join playbook is also
  packaged, `scylla-health` is available as a guarded read-only internal
  service, `scylla-remove-live` is a guarded destructive internal service, and
  `scylla-remove-dead` is a guarded coordinator-only destructive internal
  service, `scylla-replace-dead` is a guarded new-target destructive internal
  service, `scylla-repair` and `scylla-cleanup` are guarded single-target
  sensitive internal services, `jump-host-configure` is a guarded jump-only
  mutating internal service, `manager-agent` is a guarded Scylla-only Manager
  3.12 package-install internal service, `manager-server` is a guarded
  manager-only Manager 3.12 package-install internal service,
  `manager-backend-preflight`, `manager-backend-storage-discover`, and
  `manager-backend-storage-preflight` are guarded Manager-only read-only
  internal services, `manager-backend-storage-prepare` is a guarded destructive
  Manager-only internal source without an operation owner, and
  `manager-backend-local-install` is a guarded Manager-only package-install
  internal service, `monitoring-agent`
  is a guarded Scylla-only node-exporter package-install internal service,
  `monitoring-stack` is a guarded monitoring-only archive-install internal
  service, `monitoring-targets` is a guarded monitoring-only official
  target-file internal service, `manager-tasks` is a guarded manager-only
  fail-closed task-validation internal service, `storage-retire` is a guarded
  Scylla-only fail-closed storage-retirement internal service,
  `service-converge` is a guarded fail-closed unit-reconciliation internal
  service, `scylla-cluster-shutdown` is a guarded fail-closed full-cluster
  guest-shutdown validation internal service, `os-upgrade-preflight` is a
  guarded read-only role-aware transition-validation internal service,
  `os-upgrade-in-place` is a guarded sensitive validation-only internal service
  that always refuses the unapproved transition without mutation,
  `os-reprovision-prepare` is a guarded destructive preparation-validation
  internal service that always blocks before provider or host mutation, and
  `os-upgrade-postcheck` is a guarded read-only verifier that always blocks
  current validation-only source results with
  `source-upgrade-not-performed`. All catalog sources are packaged, but no
  supported OS-upgrade path can currently prove completed mutation.
  Evidence collection is a read-only
  internal API with strict schema parsing; its owner-only
  `<cluster-root>/logs/evidence.json` store requires explicit caller approval,
  a matching lock, and generation/digest guards. The
  `storage-prepare` has only fake/static coverage and has not been exercised on
  real storage; no public operation invokes it. The ScyllaDB upstream role is
  pinned by immutable Git commit as provenance but is not invoked because its
  configuration path cannot be safely constrained. Installation and
  configuration instead use narrow wrapper-owned package and exact-template
  paths. Public SSH trust orchestration, live validation of routed candidate
  collection, and public live-health and runtime operation wiring remain
  unavailable. The
  offline operation-plan resolver validates registry/catalog selection, limits,
  variables, readiness, and redacted checkpoint evidence while remaining
  write-free. A separate internal API can persist and offline-revalidate its
  immutable request/plan binding against an existing PLAN journal checkpoint.
  Another internal API can persist only the exact class-aware confirmation
  companion for an unblocked ready plan, but every unimplemented mutating public
  workflow remains blocked before that point. No public workflow creates or
  resumes either checkpoint, and neither API executes, advances the journal
  beyond PLAN, or verifies an operation. The separate internal
  `check-jump-hosts` finalizer can now verify only a fully succeeded prepared
  execution with exact durable semantic evidence and advance that operation's
  common journal through VERIFY to terminal success. The internal lifecycle
  coordinator composes that finalizer with preparation and execution for only
  this modeled read-only operation. The separate internal initiation owner can
  now create that exact prerequisite without planning or execution. A one-call
  internal coordinator composes those two owners under one matching held lock,
  and the composed path remains fake-only tested. None of these APIs is
  CLI-wired, and they do not make the public no-write checker journaled. The SSH trust,
  route, exact machine
  inventory validation, and readiness-gate library contracts are fake-tested
  but no public CLI establishes trust or runs those checks. The deployable
  Terraform graph and
  controlled runner,
  Terraform contracts, observed-state persistence, reconciliation, and
  inventory projection/refresh contracts, offline OCI adapter, strict tfvars,
  source-staging APIs, immutable saved-plan identity/drift checkpoint, and
  controlled deploy PLAN orchestration are internal and fake-tested. The
  checkpoint service itself remains subprocess-free; the orchestrator now owns
  exact staged plan creation, strict saved-plan show review, atomic promotion,
  checkpoint-first persistence, and journal composition. No CLI path
  initializes Terraform, plans infrastructure, downloads providers, applies, or
  destroys. Exact-plan class-aware apply authorization is now an internal
  immutable companion only; no-change remains authorization-free and the
  existing deploy CLI still cannot collect destructive-plan proof. The
  operation-scoped local-state safeguard is also internal and fake-tested, with
  exact backup or verified-absence checkpointing but no automatic restore. The
  internal exact-plan execution owner is now fake-runner-tested: it revalidates
  every canonical plan/authorization/safeguard/state/toolchain binding, records
  prepared intent, advances only to `IN_PROGRESS/EXECUTE`, consumes
  authorization in a durable started record, and invokes the saved plan at
  most once. Exit zero remains verification-pending; every uncertain started
  state forbids automatic retry. The internal post-apply verifier now validates
  state progression, runs only strict `terraform output -json`, reconciles and
  persists the guarded observation, records an immutable redacted verification
  companion, and leaves the journal nonterminal at VERIFY. Inventory/trust
  generation now continues only through the internal lock-bound verified-apply
  inventory owner: it writes/reuses canonical inventory and its immutable
  redacted operation companion without SSH trust collection, machine
  validation, or process execution. The subsequent internal trust owner
  consumes only already-obtained typed candidates and explicit per-key proofs,
  establishes jump then routed private trust in guarded stages, renders only
  canonical SSH trust derivatives, and persists its immutable redacted
  companion only when the exact inventory host set is current. It never scans
  hosts or runs Terraform, SSH, or Ansible. The subsequent internal
  operation-bound readiness owner consumes that complete trust companion,
  renders or exact-reuses canonical owner-only `ansible.cfg`, probes the exact
  explicit Ansible executable pair, and runs only controller-local
  `ansible-inventory --list`. It strictly reconciles normalized machine
  inventory with the persisted static inventory, builds fresh local readiness,
  and persists immutable redacted
  `terraform/plans/<operation-uuid>.terraform-apply-readiness.json` evidence.
  Exact current re-entry makes no tool call, and all remote connectivity,
  health, and playbook checks remain `not-performed`. It does not contact hosts
  or run a playbook. A subsequent internal deploy-only planning owner now
  consumes the exact verified apply/inventory/trust/readiness chain under the
  matching held deploy lock. Because the generic Ansible binding requires a
  PLAN-phase checkpoint, this post-Terraform VERIFY subphase instead persists
  immutable owner-only
  `operations/<operation-uuid>.ansible-deploy-context.json` and
  `operations/<operation-uuid>.ansible-deploy-plan.json` records. It expands
  the exact registry deploy mapping by stable logical target ID and binds
  catalog/source/command/target/variable and prerequisite-chain digests without
  running a process. Unmodeled package, bootstrap, Manager, and monitoring
  intent plus all unperformed remote connectivity, host, storage, health,
  quorum, backup, capacity, wipe-consent, and authorization evidence remain
  explicit blockers, so local readiness never makes the plan executable.
  Exact context/plan re-entry is write-free and a matching context-only prefix
  may recover. A subsequent internal deploy-prerequisite owner now revalidates
  that full chain and immutable plan, probes only the exact explicit Ansible
  executable pair, then executes exactly controller-local
  `inventory-preflight` followed by the initial complete-host-set
  `connectivity-check`. Limits and fixed SSH-only variables are derived
  internally; destination probes and caller-supplied playbooks, limits,
  variables, commands, environment, paths, or results are not accepted.
  Generation-guarded owner-only
  `operations/<operation-uuid>.ansible-deploy-prerequisite-execution.json`
  records durable intent before each call, while the independent
  `operations/<operation-uuid>.ansible-deploy-prerequisite-evidence.json`
  immutable-prefix companion retains only address-free semantic statuses,
  bounded counts, and exact provenance/command/result/evidence digests.
  Strict inventory parity and complete unique per-host connectivity results are
  required; exit zero alone is insufficient. Any started uncertain/failed
  attempt or post-invocation persistence failure requires manual recovery and
  cannot retry automatically. An exact succeeded preflight prefix may continue,
  and exact full completion re-entry makes zero process calls. Full success is
  only `deploy-prerequisites-ready` for inventory parity and initial SSH
  connectivity. It does not rewrite the immutable plan. A subsequent
  subprocess-free internal `reconcile_deploy_ansible_plan` API now reloads that
  completed execution/evidence plus the full canonical chain, recomputes and
  requires the exact original 21-position mapping and every expanded
  condition/target/policy/variable/source/command identity, and persists only
  immutable owner-only
  `operations/<operation-uuid>.ansible-deploy-effective-plan.json` as
  `deploy-scylla-vms.ansible-deploy-effective-plan/v1`. The effective companion
  marks only inventory preflight and initial connectivity `succeeded` with exact
  semantic-evidence bindings. Later read-only checks remain `not-performed`
  because the next active positions are mutating, while every mutating,
  sensitive, and destructive step remains blocked by class-specific execution
  and authorization blockers. Exact companion reuse is zero-write; changed
  journal/context/plan/evidence/readiness/catalog/source/mapping provenance
  fails closed and requires a new operation/re-plan. The API accepts no caller
  plan/status/evidence/step/variable/command/path input, invokes no runner, and
  leaves the original context/plan/evidence and common
  `IN_PROGRESS/VERIFY` journal unchanged. A separate internal
  `execute_deploy_pre_mutation_host_evidence` checkpoint now reloads that full
  chain and uses only the existing bounded, read-only `evidence-collect`
  source. It partitions the complete stable-ID host set into deterministic
  role batches, records durable intent before each controlled invocation, and
  strictly requires one role-applicable result per selected host. Its
  independently versioned owner-only execution and semantic-evidence
  companions live at
  `operations/<operation-uuid>.ansible-deploy-pre-mutation-host-evidence-execution.json`
  and
  `operations/<operation-uuid>.ansible-deploy-pre-mutation-host-evidence.json`.
  They retain only address-free OS/architecture/reboot-status/capacity/mount/
  device-set/service/role-health facts and exact provenance digests; raw output,
  addresses, provider IDs, device paths, commands, environment, routes, keys,
  and secrets are excluded. Unsupported OS/architecture facts remain bounded
  blockers rather than being coerced. Any uncertain or failed started batch is
  manual-recovery/no-retry; an exact succeeded role prefix may continue, and
  exact completion re-entry makes no process call. This is the distinct
  `pre-mutation-host-evidence` checkpoint, not the original mapping's final
  evidence step: the effective plan and common journal remain byte-for-byte
  unchanged, and mapped final evidence remains `not-performed`. The
  subprocess-free internal `reconcile_deploy_pre_mutation_host_evidence` API
  now canonically reloads that checkpoint and the complete Terraform through
  deploy-plan chain, recomputes the exact mapping, and persists immutable
  owner-only
  `operations/<operation-uuid>.ansible-deploy-host-evidence-reconciliation.json`
  as
  `deploy-scylla-vms.ansible-deploy-host-evidence-reconciliation/v1`.
  It evaluates only bounded platform, reboot, service, capacity, mount, and
  role-applicable device gates. Unsupported or unavailable facts remain
  explicit blockers; no package, storage ownership, cluster-empty, health,
  quorum, backup, or capacity-safety conclusion is inferred. The first
  inventory/connectivity steps remain evidence-bound `succeeded`, the distinct
  checkpoint is bound only in reconciliation metadata, and the mapped final
  evidence step stays `not-performed`. Only the next role-scoped `base-os`
  steps with all applicable gates passed can be labeled
  `evidence-ready-authorization-required`; that reconciliation does not itself
  make them eligible or executable, and every later storage/package/
  configuration/bootstrap/health/Manager/monitoring step remains blocked or
  not performed. Exact reuse is
  zero-write, every provenance or mapping conflict fails closed, and the API
  creates no authorization or execution intent, calls no runner, and leaves
  the common journal at `IN_PROGRESS/VERIFY`. The internal
  `authorize_deploy_base_os` continuation now revalidates that complete chain
  and derives the entire authorizable scope only from exact
  `evidence-ready-authorization-required` statuses. It accepts only a normalized
  ordinary interactive or PLAN-permitted `--yes` approval; destructive flags
  and scope proof are inapplicable. It persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-base-os-authorization/v1` at
  `operations/<operation-uuid>.ansible-deploy-base-os-authorization.json`,
  binding the journal, context/plans/reconciliations/evidence/readiness/source/
  catalog and exact `base-os` step/target/digest scope. Exact reuse is
  zero-write; changed proof or provenance requires a new plan and operation.
  The authorization owner leaves authorization unconsumed and all step statuses
  unchanged. The internal `execute_deploy_base_os` continuation accepts only
  canonical identity, the matching held deploy lock, a controlled runner, and
  an exact validated Ansible executable/toolchain dependency. It derives every
  scope, stable-ID limit, typed Ubuntu 24.04/image-architecture variables,
  guest-architecture parity, and command from the immutable chain, then writes
  owner-only
  `deploy-scylla-vms.ansible-deploy-base-os-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-base-os-evidence/v1` companions at
  `operations/<operation-uuid>.ansible-deploy-base-os-execution.json` and
  `operations/<operation-uuid>.ansible-deploy-base-os-evidence.json`.
  Each exact scope is durably `prepared`, then `started` immediately before its
  sole controlled call; `started` is the immutable authorization-consumption
  boundary. Strict result parsing and address-free semantic evidence precede
  terminal success. Any uncertain start, timeout, interruption, failed/
  unreachable/malformed result, or post-call persistence failure permanently
  requires manual recovery and forbids automatic retry. Exact completed re-entry
  makes no process call. This owner does not reboot, update the effective plan,
  run another playbook, or change the `IN_PROGRESS/VERIFY` journal. The
  subprocess-free internal `reconcile_deploy_base_os_result` continuation now
  canonically reloads that complete chain and requires terminal-success
  execution plus complete semantic evidence for the exact authorized scope.
  It persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-base-os-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-base-os-reconciliation.json`
  without rewriting any earlier plan, reconciliation, authorization, execution,
  evidence, or journal record. Exact executed `base-os` instances become
  evidence-bound `succeeded`; changed and already-current hosts remain separate
  bounded counts. Any reboot-required host adds explicit `reboot-required` and
  `reboot-handling-not-performed` blockers and keeps every later active step
  blocked while performing no reboot or reconnect. Without that blocker, only
  the exact next ordered gate whose independent current evidence is proven may
  become `evidence-ready-authorization-required` for mutating work or
  `eligible` for read-only work; the current jump-host path can advance only
  `jump-host-configure`, and no later step is leapfrogged. Unexecuted `base-os`
  scopes, final mapped evidence, later storage/package/configuration/bootstrap/
  health/Manager/monitoring work, authorization/execution, finalization, and
  public deploy wiring remain pending. Exact unchanged re-entry is zero-write;
  every incomplete, uncertain, stale, drifted, or conflicting prefix fails
  closed. The internal `plan_and_authorize_deploy_reboots` continuation now
  canonically reloads that complete chain, derives reboot targets only from
  exact successful `base-os` semantic evidence marked `reboot-required`, and
  persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-reboot-plan/v1` then
  `deploy-scylla-vms.ansible-deploy-reboot-authorization/v1` at
  `operations/<operation-uuid>.ansible-deploy-reboot-plan.json` and
  `operations/<operation-uuid>.ansible-deploy-reboot-authorization.json`.
  The plan preserves exact base-OS execution order, stable-ID tie-breaking,
  serial one, current inventory/trust/route/connectivity bindings, and an
  address-free route-dependency digest. It refuses an order that places a
  routed host before its selected jump dependency. Every planned step requires
  a future reconnect, exact identity/trust revalidation, machine evidence, and
  reboot-clear checkpoint before the next step. Reboot-required deploy work is
  mutating and accepts only ordinary interactive or PLAN-permitted `--yes`
  approval; destructive proof is inapplicable. No-reboot state returns
  `not-required` and creates no reboot artifacts. Exact plan-only recovery and
  unchanged reuse are allowed; changed proof or provenance fails closed.
  At that planning boundary authorization remains unconsumed and reconnect is
  not performed. The internal `execute_deploy_reboots` continuation now
  canonically reloads the complete chain and exact reboot plan/authorization
  under the held deploy lock, derives every serial-one stable-ID scope,
  variable, source, and command internally, and persists owner-only
  `deploy-scylla-vms.ansible-deploy-reboot-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-reboot-evidence/v1` companions at
  `operations/<operation-uuid>.ansible-deploy-reboot-execution.json` and
  `operations/<operation-uuid>.ansible-deploy-reboot-evidence.json`.
  Each target is durably `prepared` then `started`; the first `started` consumes
  authorization for the exact ordered scope before the sole controlled call.
  The hash-checked `deploy-reboot` source uses bounded
  `ansible.builtin.reboot`, fixed pre/post inactive-service gates, in-memory
  hashed boot identity, strict host-key checking, and exact Ubuntu 24.04/
  architecture identity. Success requires reconnect, changed boot identity,
  current trust, unchanged machine identity, safe services, and absence of
  `/var/run/reboot-required`. Its strict address-free result and persisted
  semantic evidence omit raw boot IDs, addresses, provider IDs, routes, keys,
  facts, commands, environment, credentials, secrets, and module output.
  A strict succeeded prefix alone may continue to the next planned target;
  every started crash/timeout/interruption/unreachable/nonzero/malformed/
  non-UTF-8/oversized result, gate mismatch, drift, or post-call persistence
  failure is manual-recovery/no-retry and never skips or reboots automatically.
  Complete exact re-entry makes no process call. The reboot execution owner
  leaves the journal and deploy-step reconciliations unchanged at
  `IN_PROGRESS/VERIFY`. The subprocess-free internal
  `reconcile_deploy_post_reboot_plan` continuation now reloads and revalidates
  the complete canonical deploy and reboot chain under the held deploy lock.
  It records the no-reboot branch as `not-required` without reboot artifacts,
  or requires exact terminal-success execution, consumed authorization, ordered
  semantic evidence, reconnect, changed boot identity, identity/trust/machine
  validation, service safety, and reboot-clear proof for every planned target.
  Missing, partial, reordered, failed, uncertain, stale, drifted, or conflicting
  evidence fails before persistence. The owner recomputes the complete deploy
  mapping and persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-reboot-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-post-reboot-reconciliation.json`.
  Base-OS successes remain evidence-bound; completed reboot handling clears only
  its exact blockers, and only the immediate proven `jump-host-configure` scope
  may become `evidence-ready-authorization-required`. No later step becomes
  eligible. Exact re-entry is zero-write, and the redacted report contains only
  bounded states, counts, stable-ID set/order digests, blockers, and provenance
  digests. This continuation creates no authorization/execution record, invokes
  no runner or toolchain, changes no earlier companion or journal, and performs
  no reboot. The internal `authorize_deploy_jump_host_configure` continuation
  now revalidates that full chain and derives its complete scope only from exact
  mapping-position-four `jump-host-configure` instances marked
  `evidence-ready-authorization-required`. It accepts only normalized ordinary
  interactive or PLAN-permitted `--yes` approval; destructive proof and
  caller-provided steps, targets, limits, variables, commands, paths, or scope
  are inapplicable. It persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-authorization/v1` at
  `operations/<operation-uuid>.ansible-deploy-jump-host-configure-authorization.json`,
  binding the post-reboot reconciliation and exact context/plan/evidence/
  inventory/trust/readiness/source/catalog/journal and step-intent digests.
  Exact unchanged reuse is zero-write; changed proof, scope, or provenance
  requires a new plan and operation. The internal
  `execute_deploy_jump_host_configure` continuation now consumes that immutable
  authorization only through a durable started execution record. It derives one
  exact jump stable-ID call at a time, the role-level configuration
  authorization, PermitOpen routes, rendered policy, typed variables, and
  anchored command from canonical state, then accepts only strict semantic
  changed/noop/failure evidence. Owner-only
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-evidence/v1` companions
  retain address-free state, policy/route/config/result/source digests, and
  validation/reload/restoration truth. Prepared intent may safely resume before
  invocation; any started ambiguity, validation/reload failure, malformed or
  failed result, post-call drift, or persistence failure requires manual
  recovery and permanently forbids automatic retry. Complete exact re-entry is
  zero-process. The immutable authorization, post-reboot reconciliation,
  journal, and every step status remain unchanged. Next-plan reconciliation,
  connectivity rerun, later stages, finalization, CLI, and public workflow
  remain pending. The subprocess-free internal
  `reconcile_deploy_jump_host_configure_result` continuation now reloads that
  complete chain under the matching held deploy lock and requires terminal
  success plus one exact semantic entry for every authorized jump target.
  Changed and no-change results must both prove the current policy,
  PermitOpen-route and configuration digests, successful sshd validation,
  reload success exactly when changed, and unambiguous restore-not-required
  evidence. Missing, extra, duplicate, wrong-target, partial, failed,
  uncertain, stale, or drifted state fails before persistence. It writes only
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-jump-host-configure-reconciliation/v1`
  at
  `operations/<operation-uuid>.ansible-deploy-post-jump-host-configure-reconciliation.json`.
  Exact jump-host steps become evidence-bound `succeeded`; only the immediate
  next active mapping whose independent gates are proven becomes read-only
  `eligible` or mutating `evidence-ready-authorization-required`. For the
  current mapping this makes only the final-routes connectivity check eligible;
  non-jump `base-os` is derived as the next gate only if all earlier mappings
  are inactive and its unaffected host evidence remains current. Storage,
  package, configuration, bootstrap, health, Manager, monitoring, final
  evidence, finalization, and public deploy stages remain blocked or not
  performed. Exact reuse is zero-write; the owner invokes no runner/toolchain,
  creates no authorization/execution intent, rewrites no trust, and leaves the
  common journal at `IN_PROGRESS/VERIFY`. Next-gate execution/reconciliation
  and every later deploy stage remain pending. The internal
  `execute_deploy_final_routes_connectivity` continuation now accepts only
  canonical operation identity, the matching held deploy lock, the controlled
  runner, and an exact validated Ansible toolchain. It reloads the complete
  post-jump-host chain, derives the sole eligible final-routes
  `connectivity-check`, exact jump stable-ID limits, and allowlisted
  inventory-route destination role/port pairs, then durably records started
  intent before invoking the anchored playbook. Only RFC 1918 assigned routes
  are accepted; arbitrary probes, public destinations, private-target SSH, and
  caller-supplied commands or variables remain impossible. Owner-only
  `deploy-scylla-vms.ansible-deploy-final-routes-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-final-routes-evidence/v1` companions at
  `operations/<operation-uuid>.ansible-deploy-final-routes-{execution,evidence}.json`
  retain only address-free status/count/digest evidence. Any started
  uncertainty, process or semantic failure, malformed output, drift, or
  post-call persistence failure requires manual recovery and forbids retry;
  exact success re-entry is zero-process. The separate
  `reconcile_deploy_final_routes_connectivity` owner persists immutable
  `deploy-scylla-vms.ansible-deploy-post-final-routes-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-post-final-routes-reconciliation.json`,
  marks only the exact route check evidence-bound `succeeded`, and derives only
  the immediate next mapping gate. In the current mapping that may make
  non-jump `base-os` authorization-required when all independent evidence is
  current; no later stage leapfrogs it. The journal remains
  `IN_PROGRESS/VERIFY`. The separate internal
  `authorize_deploy_non_jump_base_os` continuation now derives only that exact
  mapping-position-six `base-os` scope from the immutable post-final-routes
  reconciliation. It rejects jump hosts, any overlap with the earlier
  immutable jump-scope base-OS authorization, missing/extra/non-ready targets,
  uncertain execution, and current inventory/trust/readiness/host-evidence/
  source/catalog/journal drift. Interactive approval and PLAN-permitted
  `cli-yes` are the only accepted ordinary proof methods; destructive and
  narrow consent are inapplicable. Owner-only immutable
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-authorization/v1` is
  written only at
  `operations/<operation-uuid>.ansible-deploy-non-jump-base-os-authorization.json`.
  It binds the exact step/source/command/variable/target identity, final-routes
  and pre-mutation host evidence, and the complete canonical provenance chain.
  Exact reuse is zero-write, authorization remains unconsumed, execution is
  unavailable, and the journal and every earlier artifact remain unchanged.
  The internal `execute_deploy_non_jump_base_os` continuation now revalidates
  that complete chain and exact authorization, then derives only the
  mapping-position-six `non-jump-managed-hosts` scope, sorted non-jump stable
  IDs, Ubuntu 24.04 architecture variables, and anchored `base-os` command.
  It rejects jump/earlier-scope overlap, non-ready host or route evidence,
  stale or consumed authorization, uncertain history, and provenance drift
  before invocation. Distinct owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-evidence/v1` companions
  live at
  `operations/<operation-uuid>.ansible-deploy-non-jump-base-os-{execution,evidence}.json`.
  A retry-safe prepared record may precede effect; the durable started record
  consumes the immutable whole-scope authorization immediately before the
  controlled call. Strict semantic parsing requires every selected stable ID
  and coherent Ubuntu/architecture/applied/changed/reboot/prerequisite/timesync
  evidence; exit zero alone is insufficient. Any started uncertainty is
  permanent manual-recovery/no-retry, while complete exact re-entry makes no
  process call. The journal and all prior artifacts remain unchanged.
  The subprocess-free internal `reconcile_deploy_non_jump_base_os_result`
  continuation now reloads that full canonical chain and requires exact
  terminal success plus complete unique semantic evidence for every authorized
  non-jump target. It persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-non-jump-base-os-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-post-non-jump-base-os-reconciliation.json`
  without rewriting earlier records. Exact mapping-position-six `base-os`
  becomes distinctly evidence-bound `succeeded`, retaining separate changed,
  already-current, and reboot-required counts. Any reboot-required target
  blocks every later active step with reboot handling explicitly
  `not-performed`; earlier jump-scope reboot artifacts are not reused. With no
  reboot, only the derived immediate mapping may advance. In the current
  mapping that makes Scylla-only read-only `storage-discover` eligible when
  current independent gates pass; storage preflight/preparation, packages,
  configuration, bootstrap, health, Manager, monitoring, and final evidence
  do not leapfrog it. Exact unchanged re-entry is zero-write, incomplete or
  uncertain evidence and provenance drift fail closed, and the report exposes
  only bounded counts, statuses, blockers, and digests. Non-jump reboot
  execution/handling, storage-discovery execution, later stages, finalization,
  CLI, and public deploy wiring remain pending.
  The separate internal
  `plan_and_authorize_deploy_non_jump_reboots` continuation now derives only
  successful non-jump `base-os` results that explicitly require reboot. It
  writes distinct immutable owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-plan/v1` and
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-authorization/v1` records
  at
  `operations/<operation-uuid>.ansible-deploy-non-jump-reboot-{plan,authorization}.json`;
  the earlier jump-scope reboot records are never reused or overwritten.
  Target order is serial one and preserves exact non-jump base-OS execution
  order while binding configured jump-route, final-routes, inventory, trust,
  readiness, source, catalog, reconciliation, and journal evidence. Every
  target requires future reconnect, identity/trust, machine-evidence,
  service-safety, and reboot-clear verification before continuation.
  Interactive approval and PLAN-permitted `cli-yes` are the only ordinary
  proof methods; destructive proof is refused. Missing approval or a failed
  authorization write leaves only an exact recoverable plan prefix. No-reboot
  evidence creates no artifact and preserves the eligible `storage-discover`
  branch. Exact reuse is zero-write, reports are address-free and digest-bound,
  authorization remains unconsumed, execution stays unavailable, and the
  journal remains `IN_PROGRESS/VERIFY`. This planning boundary performs neither
  execution nor post-reboot reconciliation.
  The internal `execute_deploy_non_jump_reboots` continuation now reloads that
  full chain under the matching held deploy lock and derives the exact
  immutable non-jump target order and typed `deploy-reboot` variables from
  canonical records. It writes distinct owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-evidence/v1` companions at
  `operations/<operation-uuid>.ansible-deploy-non-jump-reboot-{execution,evidence}.json`.
  Each target runs serial one only after durable `prepared` and `started`
  intent; the first started record consumes the distinct whole-scope
  authorization without rewriting it. Strict address-free evidence requires
  exact host/role/Ubuntu/architecture identity, reconnect, changed boot
  identity, current trust, machine evidence, pre/post service safety, and
  reboot-clear truth. A succeeded prefix may continue to the next immutable
  target. Any started process, semantic, drift, or persistence uncertainty is
  permanent manual-recovery/no-retry and forbids skip, continuation, rollback,
  or trust rewrite. Exact complete re-entry makes no process call. Earlier
  jump-scope reboot artifacts and the common `IN_PROGRESS/VERIFY` journal stay
  byte-for-byte unchanged.
  The subprocess-free internal
  `reconcile_deploy_post_non_jump_reboot_plan` continuation now reloads that
  full chain and persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-non-jump-reboot-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-post-non-jump-reboot-reconciliation.json`.
  A no-reboot result requires every distinct non-jump reboot artifact to be
  absent and preserves the independently derived next gate. A reboot-required
  result requires the exact complete ordered execution, consumed execution
  authorization, no uncertainty, and true reconnect, boot-change, identity,
  trust, machine-evidence, pre/post service-safety, and reboot-clear gates for
  every target. Partial, failed, started, extra, reordered, stale, or drifted
  state fails before persistence. Only after complete proof are reboot blockers
  cleared and the first remaining active mapping reconsidered; in the current
  mapping this makes only read-only Scylla `storage-discover` eligible.
  Everything later remains blocked or not performed. Exact re-entry is
  zero-write, reports remain address-free and digest-bound, prior artifacts and
  the journal remain unchanged, and no runner, CLI, or public workflow is
  wired.
  The internal `execute_deploy_storage_discovery` continuation now reloads
  that complete chain, derives the exact eligible sorted Scylla stable-ID
  scope, and invokes only the packaged, hash-checked `storage-discover`
  playbook through the controlled Ansible service. It writes durable started
  intent before the call and persists owner-only
  `deploy-scylla-vms.ansible-deploy-storage-discovery-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-storage-discovery-evidence/v2` records at
  `operations/<operation-uuid>.ansible-deploy-storage-discovery-execution.json`
  and
  `operations/<operation-uuid>.ansible-deploy-storage-discovery-evidence.json`.
  Strict semantic evidence keeps only bounded statuses/counts and hashed
  device/signature/ownership/topology identities; raw device paths, serials,
  output, addresses, commands, variables, environment, and credentials are
  excluded. A started uncertain outcome is permanent
  manual-recovery/no-retry, while exact successful re-entry makes no process
  call.
  The subprocess-free `reconcile_deploy_storage_discovery` continuation
  persists immutable
  `deploy-scylla-vms.ansible-deploy-post-storage-discovery-reconciliation/v1`
  at
  `operations/<operation-uuid>.ansible-deploy-post-storage-discovery-reconciliation.json`.
  It marks only the exact storage-discovery step succeeded and may make only
  the immediate read-only `storage-preflight` gate eligible. It creates no
  mutation authorization, leapfrogs no later gate, and leaves the common
  `IN_PROGRESS/VERIFY` journal byte-for-byte unchanged.
  The internal `execute_deploy_storage_preflight` continuation reloads that
  complete chain, derives the exact sorted Scylla scope and typed
  desired-policy/manifest/discovery projection, and invokes only the packaged
  read-only `storage-preflight` playbook in check mode. Durable started intent
  and owner-only
  `deploy-scylla-vms.ansible-deploy-storage-preflight-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-storage-preflight-evidence/v1` companions
  provide permanent no-retry handling after any uncertain call. Evidence
  retains only disposition/action enums, counts, capacity, blocker/status
  digests, and hashed device sets; addresses, provider IDs, device paths,
  serials, commands, variables, output, and credentials are excluded.
  The subprocess-free `reconcile_deploy_storage_preflight` persists immutable
  `deploy-scylla-vms.ansible-deploy-post-storage-preflight-reconciliation/v1`.
  Exact valid preflight results mark only mapping-position-eight succeeded.
  Blocked hosts remain blocked, `owned-noop` hosts are not authorized or
  rewritten, and only `prepare-required` hosts enter the immediate
  `storage-prepare` authorization scope. Wipe-required host/device-set scope is
  reported separately for explicit consent. The internal
  `authorize_deploy_storage_prepare` continuation now persists only immutable
  `deploy-scylla-vms.ansible-deploy-storage-prepare-authorization/v1` at
  `operations/<operation-uuid>.ansible-deploy-storage-prepare-authorization.json`.
  It reloads the complete chain, derives only exact `prepare-required` hosts,
  and requires ordinary approval plus separate destructive-class and exact
  preparation-scope proof. `--yes` alone never bypasses those proofs. Exact
  wipe consent is an independent digest-bound proof required only for the
  wipe-required subset and is rejected for non-wipe, narrower, broader, or
  mismatched scope. The authorization owner leaves the immutable record
  unconsumed, `show` validates it without exposing protected scope detail, and
  that owner performs no process call, storage mutation, later-stage leapfrog,
  journal transition, finalization, CLI, or public execution wiring.
  The internal `execute_deploy_storage_prepare` continuation consumes that
  exact authorization through durable owner-only
  `deploy-scylla-vms.ansible-deploy-storage-prepare-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-storage-prepare-evidence/v1` companions at
  `operations/<operation-uuid>.ansible-deploy-storage-prepare-execution.json`
  and
  `operations/<operation-uuid>.ansible-deploy-storage-prepare-evidence.json`.
  It revalidates the complete chain, derives only sorted `prepare-required`
  scopes, records `prepared` and then `started` before each exact-one-target
  serial-one call, consumes general approval only at the first started
  boundary, and consumes wipe consent only at each exact wipe-required
  boundary. The strict role result must prove immediate device revalidation,
  exact action/disposition/device-set/provenance, mutation boundary, first
  irreversible step, and completed post-action state; exit zero alone is not
  success. Evidence retains stable IDs and bounded statuses/digests but omits
  addresses, provider IDs, device paths/serials, commands, variables, raw
  output, and credentials. Every uncertain started outcome is permanent
  manual-recovery/no-retry/no-skip/no-continue; exact completion re-entry makes
  zero process calls. The internal subprocess-free
  `reconcile_deploy_storage_prepare` continuation now persists immutable
  `deploy-scylla-vms.ansible-deploy-post-storage-prepare-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-post-storage-prepare-reconciliation.json`.
  It reloads the full chain, requires complete certain terminal success and
  exact proof consumption for every `prepare-required` target, binds each such
  result as succeeded, and combines it with current `owned-noop` preflight
  evidence without claiming a mutation. Blocked storage remains blocked. Only
  the immediate exact read-only `storage-postcheck` scope may become eligible;
  package installation and every later gate remain unavailable. The report is
  count/digest-only, `show` validates the owner-only record, exact re-entry is
  zero-write, and the common `IN_PROGRESS/VERIFY` journal remains unchanged.
  The next internal continuation, `execute_deploy_storage_postcheck`, now
  revalidates that complete chain and runs only the exact eligible
  `storage-postcheck` scopes, one stable ID at a time, in check mode through
  the controlled runner. It durably records `started` before each call and
  persists owner-only execution/evidence v1 records containing only bounded
  check summaries, capacity totals, hashed device identities, and provenance
  digests. Any failed, unknown, malformed, unreachable, interrupted, or
  uncertain result permanently requires manual recovery and is never retried.
  `reconcile_deploy_storage_postcheck` then immutably binds complete current
  success, marks only those postcheck steps succeeded, and exposes only the
  immediate `scylla-install` scopes as authorization-required. The common
  journal remains unchanged. The internal
  `authorize_deploy_scylla_install` continuation reloads that complete chain,
  derives the exact Scylla stable-ID scopes and the catalog-bound 2026.2
  package/repository/signing-key provenance, and accepts only ordinary
  interactive or `cli-yes` approval. It persists one immutable owner-only v1
  authorization under `operations/<operation-uuid>`, which `show` validates,
  while leaving it unconsumed until the separate internal
  `execute_deploy_scylla_install` owner durably records the exact first
  `started` attempt. That owner revalidates the complete chain and controlled
  Ansible toolchain, derives only the authorized serial-one stable-ID scopes,
  and persists owner-only Scylla-install execution and semantic-evidence v1
  records. Strict successful evidence requires the exact 2026.2 package set
  with `scylla-server` masked and inactive and no configuration, storage,
  tuning, Manager, or service-start action. Any uncertain started outcome is
  permanent manual-recovery/no-retry; exact completed re-entry is zero-process.
  The subprocess-free `reconcile_deploy_scylla_install` continuation then
  revalidates that complete chain and persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-scylla-install-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-post-scylla-install-reconciliation.json`.
  It accepts only exact terminal success and complete current package,
  provenance, masked/inactive-service, and prohibited-action evidence for every
  authorized Scylla target. It marks only the exact `scylla-install` scopes
  evidence-bound succeeded and advances only immediate `scylla-configure`
  scopes to authorization-required; bootstrap, agents, health, and later gates
  remain blocked. Its report is count/digest-only, `show` validates the record,
  and exact re-entry is zero-write. The common journal and prior artifacts
  remain unchanged at `IN_PROGRESS/VERIFY`. The internal
  `authorize_deploy_scylla_configure` continuation reloads that full chain and
  derives the exact Scylla target/configuration intent only from canonical
  desired state, observation, inventory, package evidence, and packaged
  source. It binds cluster/DC/rack and private identities, deterministic
  stable-ID seeds, exact 2026.2 packages, fixed data directories, the two
  wrapper-owned templates, masked/inactive service policy, and source,
  variable, command, and rendered-intent digests without persisting their
  protected values. Only ordinary interactive or `cli-yes` approval is
  accepted; destructive proof is refused. The immutable owner-only v1 record
  lives at
  `operations/<operation-uuid>.ansible-deploy-scylla-configure-authorization.json`,
  is recognized by `show`, remains unconsumed, and is exactly reusable without
  a write. The internal `execute_deploy_scylla_configure` continuation then
  derives only that exact authorized mapping-position-twelve scope and invokes
  the hash-checked `scylla-configure` playbook once per authorized target,
  serial one. Owner-only immutable-prefix
  `deploy-scylla-vms.ansible-deploy-scylla-configure-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-scylla-configure-evidence/v1` records live
  under `operations/` at the operation UUID. Durable `prepared` precedes each
  invocation, durable `started` consumes the whole authorization, and strict
  semantic success proves exact 2026.2, only the two wrapper-owned root `0644`
  configuration files and their authorized digests, masked/inactive service,
  no runtime validation, and no package, storage, tuning, firewall, SSH,
  Manager, start, or bootstrap action. Started uncertainty is permanent
  manual-recovery/no-retry; exact prepared prefixes resume and completed
  re-entry makes no process call. Reports and persisted evidence are
  value-free, `show` validates both records, and the common journal and prior
  artifacts remain unchanged at `IN_PROGRESS/VERIFY`. The subprocess-free
  `reconcile_deploy_scylla_configure` continuation now revalidates that full
  chain and persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-scylla-configure-reconciliation/v1`
  at
  `operations/<operation-uuid>.ansible-deploy-post-scylla-configure-reconciliation.json`.
  It marks only exact configuration scopes evidence-bound succeeded and
  preserves the original immutable 21-position deploy mapping. That historical
  mapping omits `scylla-bootstrap`, although the deploy procedure requires
  bootstrap before health, so reconciliation does not rewrite the plan or make
  mapped `scylla-health` eligible. It instead records
  `bootstrap-plan-required` and `bootstrap-step-unmodeled`, keeps bootstrap,
  empty-cluster, topology, seed, health, and capacity evidence
  `not-performed`, and exposes no next authorization/execution until a
  separately versioned bootstrap context/plan exists. The internal
  `plan_deploy_scylla_bootstrap` continuation now supplies that boundary with
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-context/v1` and
  `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-plan/v1` records at
  `operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-context.json`
  and
  `operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-plan.json`.
  It reloads the complete chain through post-configuration reconciliation,
  requires the original Terraform apply to prove either absent prior state or
  an initial observation from exact create-only scope, plus drift-free state
  progression, and binds an optional normalized reviewed
  new-cluster/empty-cluster/capacity proof. Missing or unknown proof facts block
  the first target. It derives the exact Scylla set, topology,
  configured initial seed, capacity and storage/config/package/source evidence,
  and serial-one order from canonical state. The configured seed is the sole
  `initial-seed` step and may become authorization-required only with complete
  empty-cluster proof; every remaining stable-identity target is
  `join-existing` and remains waiting for the preceding bootstrap plus complete
  survivor/absence/capacity/schema health evidence. Expected Host IDs remain
  explicitly unknown before start. The historical 21-step plan is not changed.
  Context is persisted before plan, an exact context-only prefix can recover,
  exact re-entry is zero-write, and conflicts fail closed. Records and reports
  retain only counts, enums, and redacted digests; `show` validates both.
  The internal
  `authorize_deploy_scylla_bootstrap_initial_seed` continuation now persists
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-authorization/v1` at
  `operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-authorization.json`.
  It reloads and exactly reproduces the full bootstrap proof/context/plan and
  derives only the first `initial-seed` target, mode, order, topology, seed,
  2026.2 package, storage, configuration, capacity, source, and empty-cluster
  bindings. Because `scylla-bootstrap` is sensitive, ordinary interactive or
  `cli-yes` approval is required; the irreversible initial membership start
  also requires a separate exact digest-only scope acknowledgement. `--yes`
  does not supply that narrow proof, destructive flags are rejected, and every
  `join-existing` step remains excluded and waiting for its health checkpoint.
  The authorization remains unconsumed, `show` validates it, and the common
  journal remains unchanged at `IN_PROGRESS/VERIFY`. The internal
  `execute_deploy_scylla_bootstrap_initial_seed` continuation now owns the
  authorized first start through distinct owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-evidence/v1` records at
  `operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-execution.json`
  and
  `operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-evidence.json`.
  It revalidates the complete context/plan/authorization and current canonical
  chain, derives the exact one initial-seed target plus protected topology,
  sole-seed, configuration, storage, package, variable, source, and command
  inputs, and durably records `prepared` then `started` before the sole
  serial-one, check-mode-refused `scylla-bootstrap` call. `started` consumes
  both ordinary and narrow authorization without rewriting it.
  Strict evidence must match the exact target/mode and hash-checked source
  contract, including pre-start service revalidation, the unmask/start
  boundary, bounded CQL readiness, and argv-form nodetool Host/ring/schema/
  streaming checks; exit zero is insufficient. A successful result persists
  only stable identity, hashed Host/ring identity, topology/version/status
  booleans, and digests. A strict failure is permanently manual-recovery and
  no-retry: a possibly joined node is preserved, while remask evidence is
  accepted only when the source proves it never joined. Any uncertainty after
  `started` forbids retry, restart, destroy, and removenode. Exact successful
  re-entry makes zero process calls; `show` validates both records. Every join
  remains unauthorized until a separate checkpoint proves current membership.
  The internal `execute_deploy_scylla_health_checkpoint` continuation now runs
  only the catalog `scylla-health` source against the exact succeeded bootstrap
  prefix, which is the initial seed at this stage. Desired waiting targets are
  bound separately and are never treated as current members. It persists
  owner-only execution, evidence, and checkpoint v1 records under
  `operations/<operation-uuid>.ansible-deploy-scylla-health-{execution,evidence,checkpoint}.json`.
  Strict completion requires exact hashed Host-ID mapping, UN topology,
  schema agreement, idle streaming, service/API/CQL/storage/version readiness,
  and no missing, extra, duplicate, transitional, or inconsistent view; exit
  zero is insufficient. Replication and backup remain `not-performed`, while
  quorum and capacity remain `unknown`, unless independent evidence proves
  those policies. The immutable bootstrap plan is not rewritten: its initial
  seed becomes health-succeeded in the separate checkpoint. The checkpoint
  retains unknown/not-performed policy facts and leaves the first waiting join
  blocked until the independently versioned join-safety continuation resolves
  the operation-specific gate policy. Started uncertainty is permanently
  no-retry, exact completion re-entry is zero-process, and `show` validates all
  three records.
  The internal `bind_deploy_scylla_join_safety` continuation now persists
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-join-safety-context/v1`,
  `deploy-scylla-vms.ansible-deploy-scylla-join-safety-evidence/v1`, and
  `deploy-scylla-vms.ansible-deploy-scylla-join-safety-reconciliation/v1`
  records at
  `operations/<operation-uuid>.ansible-deploy-scylla-join-safety-{context,evidence,reconciliation}.json`.
  It revalidates the complete bootstrap/configuration/storage/initial-seed/
  health-checkpoint chain, derives the exact sequence-two waiting target and
  current survivor/topology scope, and combines canonical target-absence,
  survivor/seed health, topology, schema, streaming, prior-membership, and
  storage evidence with one exact digest-bound independent capacity proof.
  For this initial-deploy `join-existing` class, PLAN requires capacity but
  does not require the stronger removal/replacement replication, quorum, or
  Manager backup-policy gates; those three are explicitly `not-applicable`,
  never silently passed. Failed, unknown, stale, or mismatched required
  evidence leaves stable blockers. Only sequence two can become
  `authorization-required`; every later join remains waiting. Exact re-entry is
  zero-write, local `show` validates all three records, no authorization or
  execution record is created, and the common journal remains byte-for-byte at
  `IN_PROGRESS/VERIFY`.
  The internal `authorize_deploy_scylla_join_existing` continuation now
  persists distinct immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-join-authorization/v1` at
  `operations/<operation-uuid>.ansible-deploy-scylla-join-authorization.json`.
  Its canonical API accepts only state-root/cluster identity, operation UUID,
  the matching held deploy lock, and one normalized proof. It reloads and
  exactly reproduces the full bootstrap/initial-execution/health/join-safety
  chain, then derives only the reconciled sequence-two `join-existing` target,
  current survivor/active-seed set, topology/schema/membership, package,
  storage, configuration, capacity, source, and safety bindings as redacted
  counts and digests. `scylla-bootstrap` remains sensitive: ordinary
  interactive or `cli-yes` approval plus a separate exact target/mode/scope
  acknowledgement is required, so `--yes` alone is insufficient. Destructive
  flags and proof are refused. No approval bypasses target absence, capacity,
  survivor/seed health, schema, streaming, topology, trust, readiness, source,
  journal, or drift checks. Only the first join is authorized; every later join
  remains waiting. Local `show` validates the record, and the common journal
  remains byte-for-byte at `IN_PROGRESS/VERIFY`.
  The internal `execute_deploy_scylla_first_join` continuation now reloads the
  complete immutable bootstrap, initial-seed, current-health, join-safety,
  authorization, source, catalog, and journal chain and derives only the
  authorized reconciled sequence-two target. It persists owner-only
  `ansible-deploy-scylla-join-execution.json` and
  `ansible-deploy-scylla-join-evidence.json` records under the operation UUID.
  Retry-safe prepared state precedes durable started intent; started consumes
  both ordinary and narrow approval without rewriting authorization. Only the
  hash-checked, exact-one-target, serial-one, check-mode-refused
  `scylla-bootstrap` source may run, and strict target/mode/prerequisite,
  pre-start, CQL, membership, topology, schema, and streaming evidence is
  required beyond exit zero. Exact success re-entry invokes no process. Any
  post-start uncertainty is permanent manual-recovery/no-retry. Later joins,
  public/CLI wiring, prior records, and the VERIFY journal remain unchanged;
  local `show` validates both redacted execution artifacts. The internal
  `execute_deploy_scylla_post_join_health` continuation now owns that next
  checkpoint through distinct owner-only join-health execution, evidence, and
  reconciliation v1 records under `operations/<operation-uuid>`. It does not
  infer cluster health from bootstrap success: the pre-join checkpoint covers
  only the initial seed, so it runs the existing hash-checked
  `scylla-health` source against the exact complete current set of the initial
  seed plus sequence-two target. Strict evidence must prove exact hashed
  membership, all members Up Normal, cross-view topology/schema agreement,
  idle streaming, service/API/CQL readiness, and current storage,
  configuration, and source provenance. Durable started intent precedes the
  sole process call; every post-start uncertainty is permanent no-retry.
  Exact complete re-entry is zero-process/zero-write, while an exact
  execution/evidence-only prefix may recover reconciliation without rerunning
  health. Reconciliation advances only sequences one and two and evaluates at
  most sequence three. Replication and backup remain `not-performed`, and
  quorum and capacity remain `unknown`, so the next join stays blocked pending
  its distinct operation-specific safety boundary; all later joins remain
  waiting. Local `show` validates all three redacted records. Prior artifacts,
  the VERIFY journal, public/CLI wiring, and `UPSTREAM_TODO.md` remain
  unchanged.
  The internal `bind_deploy_scylla_sequence_three_join_safety` continuation
  now owns the immediate next safety boundary through distinct owner-only
  sequence-three context, evidence, and reconciliation v1 records under
  `operations/<operation-uuid>`. It canonically revalidates successful
  sequence-two execution and consumed authorization, the fresh post-first-join
  complete-set health checkpoint, the immutable bootstrap plan, current
  infrastructure/Ansible provenance, and the unchanged VERIFY journal. It
  derives only contiguous sequence three and requires exact canonical
  membership, health, topology, schema, streaming, target absence,
  storage/configuration/package, trust/route/readiness, and competing-operation
  gates plus independent backup-policy, capacity, quorum, and replication
  proofs. Unknown, failed, stale, missing, duplicate, or drifted evidence
  remains blocked. Only exact all-pass evidence may mark sequence three
  `authorization-required`; every later sequence remains waiting. Exact-prefix
  recovery, zero-write reuse, redaction, owner-only persistence, and local
  `show` validation are enforced. Authorization, execution, journal
  transition, and public/CLI wiring remain unavailable.
  The internal `authorize_deploy_scylla_sequence_three_join` continuation now
  persists a distinct owner-only sequence-three join authorization v1 record
  under `operations/<operation-uuid>`. It canonically reproduces the full chain
  through successful sequence-two execution, fresh complete-set post-join
  health, exact sequence-three safety, current infrastructure/Ansible state,
  and the unchanged VERIFY journal. Only exact reconciled sequence three is in
  scope; later joins stay waiting. Sensitive authorization requires ordinary
  interactive or `cli-yes` approval plus a separate digest-only
  target/mode/scope acknowledgement, so `cli-yes` alone is insufficient;
  destructive proof is refused. The immutable authorization remains
  unconsumed with execution unavailable. Exact reuse writes nothing, local
  `show` validates the redacted record, and no process, CLI/public wiring, or
  journal transition is added.
  The internal `execute_deploy_scylla_sequence_three_join` continuation now
  owns only that authorized reconciled target through distinct owner-only
  sequence-three execution and semantic-evidence v1 records. It canonically
  reloads the complete chain through successful sequence two, fresh post-first-
  join health, sequence-three safety/authorization, current infrastructure and
  Ansible provenance, source/catalog, and the unchanged VERIFY journal.
  Retry-safe prepared state precedes durable started intent; started consumes
  ordinary and narrow authorization without rewriting it. Only the hash-
  checked, exact-one-target, serial-one, check-mode-refused
  `scylla-bootstrap` source may run. Strict target/mode/prerequisite,
  provenance, pre-start, CQL, membership, topology, schema, and streaming
  evidence is required beyond exit zero and is persisted before terminal
  success. Every post-start uncertainty is permanent manual-recovery/no-retry;
  prepared-only recovery is safe, exact success re-entry invokes no process or
  write, all later joins remain waiting, and post-sequence-three health remains
  not-performed. Local `show` validates both redacted records. Prior artifacts,
  the VERIFY journal, CLI/public wiring, and `UPSTREAM_TODO.md` remain
  unchanged. The next internal slice is fresh complete-current-set health and
  reconciliation after sequence three.
  The internal
  `execute_deploy_scylla_post_sequence_three_join_health` continuation now
  owns that checkpoint through distinct owner-only execution, evidence, and
  reconciliation v1 records under `operations/<operation-uuid>`. It
  canonically revalidates the full chain through terminal sequence-three
  execution with consumed proofs, then runs only the existing hash-checked
  read-only `scylla-health` source against the exact initial-seed plus
  sequence-two plus sequence-three set. Strict evidence requires unique hashed
  membership, every member Up Normal, cross-view topology/schema agreement,
  idle streaming, service/API/CQL readiness, and current storage,
  configuration, and source provenance. Backup/replication remain
  `not-performed`; capacity/quorum remain `unknown`. Durable `started` intent
  precedes the sole call, every post-start uncertainty is permanent no-retry,
  and exact complete re-entry is zero-process/zero-write. Reconciliation
  clears only sequence-three health: a later join waits for its own versioned
  safety context, while no later plan step reports bootstrap-sequence-complete
  and next-step-not-required. Local `show` validates all three redacted
  companions. Prior artifacts, the VERIFY journal, public/CLI wiring, and
  `UPSTREAM_TODO.md` remain unchanged.
  The internal `bind_deploy_scylla_later_join_safety` continuation now owns
  the safety-only boundary for the first unfinished planned join after
  sequence three. It derives that sequence exclusively from the immutable
  bootstrap plan and canonical contiguous completed-prefix plus latest fresh
  complete-set health records; callers cannot choose sequence, target, order,
  mode, or runtime values. Immutable owner-only later-join context,
  evidence, and reconciliation v1 records are keyed by derived sequence so
  sequence four and every later sequence `>=4` can coexist without a per-node
  module. A completed bootstrap plan
  returns strict `not-required`, accepts no proofs, and writes nothing.
  Otherwise exact all-pass canonical and independent policy gates may mark
  only the derived immediate join `authorization-required`; unknown remains a
  blocker and every later join stays waiting. Exact-prefix recovery,
  zero-write reuse, fail-closed sequence/proof/provenance conflict handling,
  redaction, and local `show` validation are enforced. Authorization,
  execution, health calls, journal transition, and public/CLI wiring remain
  unavailable; `UPSTREAM_TODO.md` remains unchanged.
  The internal `authorize_deploy_scylla_later_join` continuation now
  generically authorizes only that safety reconciliation's exact first
  unfinished `join-existing` sequence `>=4`, without a per-node module or
  caller-selected sequence, target, mode, order, scope, or runtime value. A
  completed bootstrap sequence accepts no proof, writes nothing, and returns
  `not-required`. Otherwise it revalidates the complete current chain, binds
  the exact completed prefix, target, membership/topology/schema/streaming,
  package/storage/configuration/capacity, independent policy, source, and
  safety identities through redacted counts, enums, and digests, and excludes
  every later waiting step. Sensitive approval requires ordinary interactive
  or `cli-yes` approval plus a separate exact digest-only
  target/mode/sequence/scope acknowledgement; `cli-yes` alone is insufficient
  and destructive proof is refused. The owner-only immutable authorization
  stays unconsumed with execution unavailable, supports zero-write exact
  reuse, leaves prior records and the VERIFY journal unchanged, and is
  validated by local `show`. Execution, health, CLI/public wiring, and
  `UPSTREAM_TODO.md` remain unchanged.
  The internal `execute_deploy_scylla_later_join` continuation now derives only
  the exact authorized first unfinished `join-existing` sequence `>=4` from the
  immutable bootstrap, latest-health, safety, and authorization chain. It
  accepts no caller-selected sequence, target, mode, order, scope, variables,
  command, result, or retry controls. Sequence-keyed owner-only
  execution/evidence v1 records bind the exact sequence; durable `started`
  consumes both approvals before one
  hash-checked `scylla-bootstrap` call, strict semantic evidence precedes
  terminal success, and every post-start uncertainty is manual-recovery/
  no-retry. Prepared recovery is pre-invocation only and completed re-entry is
  zero-process/zero-write. Later joins remain waiting for separate fresh
  complete-set health and safety. Local `show` validates both redacted records;
  the VERIFY journal, public/CLI surface, and `UPSTREAM_TODO.md` remain
  unchanged.
  The internal `execute_deploy_scylla_post_later_join_health` continuation
  derives the exact successful sequence `>=4` from those canonical records and
  runs the existing hash-checked read-only `scylla-health` source over the
  complete current stable-ID set. Sequence-keyed immutable execution,
  evidence, and reconciliation records require complete unique Up Normal
  membership, cross-view identity/topology/schema agreement, idle streaming,
  service/API/CQL readiness, and current storage/configuration provenance.
  Backup/replication remain `not-performed`; capacity/quorum remain `unknown`.
  Durable `started` uncertainty is permanent no-retry, while completed re-entry
  is zero-process/zero-write. Reconciliation reports completion or exposes
  only the next derived sequence for its separate safety stage; it does not
  collect proofs, authorize, execute, change the VERIFY journal, or add
  public/CLI wiring. Local `show` validates every redacted sequence record and
  `UPSTREAM_TODO.md` remains unchanged.
  The internal `reconcile_deploy_scylla_post_bootstrap` continuation now
  bridges an exactly completed bootstrap sequence back into the historical
  immutable 21-position deploy mapping without rewriting that mapping or any
  prior plan/reconciliation. It canonically validates every contiguous
  terminal-success bootstrap step, consumed ordinary/narrow authorization,
  strict semantic evidence, and the final fresh complete-current-set health
  family appropriate to the plan's last sequence. Its separate immutable
  owner-only
  `operations/<operation-uuid>.ansible-deploy-scylla-post-bootstrap-reconciliation.json`
  companion marks mapped `scylla-health` satisfied by that exact final health
  evidence and advances only immediate `manager-server` to
  `evidence-ready-authorization-required`. Later Manager/monitoring/final
  gates remain blocked or not performed; replication/backup remain
  `not-performed` and quorum/capacity remain `unknown`. Exact reuse is
  zero-write, drift and incomplete or ambiguous history fail closed, local
  `show` validates the redacted record, and the VERIFY journal, CLI/public
  surface, and `UPSTREAM_TODO.md` remain unchanged.
  The internal mapped `manager-server` continuation now stores one immutable
  ordinary authorization and then an exact generation-guarded execution plus
  semantic-evidence prefix for the canonical manager stable ID. Execution
  derives the Ubuntu 24.04/Manager 3.12 install-only payload and anchored
  command from current canonical state, durably consumes authorization at
  `started`, invokes the hash-checked source once, and accepts only strict
  installed/no-change evidence with `scylla-manager` masked/inactive and all
  backend, configuration, setup, registration, task, and service-start actions
  absent. Any uncertain started outcome is manual-recovery/no-retry; exact
  success re-entry is zero-process/zero-write. The journal and bridge remain
  unchanged at `IN_PROGRESS/VERIFY`, local `show` validates but does not
  project the two redacted companions, and no CLI/public wiring or upstream
  workaround is added.
  The internal `reconcile_deploy_manager_server_result` continuation now
  reloads that exact terminal-success chain and persists a separate immutable
  post-Manager reconciliation. It marks only mapped `manager-server`
  evidence-bound succeeded, proves the historical 21-position mapping
  unchanged, and evaluates only the immediate next active gate from current
  canonical evidence. A ready mutating gate becomes only
  `evidence-ready-authorization-required`; no backend configuration,
  registration, Manager start, Manager-health inference, tool call, or public
  wiring occurs. Exact reuse is zero-write, conflicts fail closed, local
  `show` validates the bounded redacted record, and the VERIFY journal and all
  prior artifacts remain unchanged.
  The internal mapped `monitoring-stack` continuation now stores one immutable
  ordinary authorization for the exact mapping-position-fifteen monitoring
  stable ID exposed by that reconciliation. It derives Ubuntu 24.04
  architecture, the digest-pinned official Scylla Monitoring 4.16.0 archive
  and component/source provenance, and archive-install-only policy from
  canonical state. Interactive or PLAN-permitted `cli-yes` approval is
  required; destructive and narrow proof are refused. Docker installation or
  image pulls, Compose/auth/targets, containers or service start, public binds,
  Manager registration, Scylla start, and secrets remain forbidden.
  Authorization is unconsumed and execution unavailable; exact reuse is
  zero-write, drift fails closed, local `show` validates the redacted record,
  and no process, journal change, CLI/public wiring, or upstream workaround is
  added.
  The corresponding internal exact execution owner now derives that sole
  monitoring target, Scylla Monitoring 4.16.0 archive/component provenance,
  install-only payload, and anchored command from current canonical state.
  It durably consumes authorization at `started`, invokes the hash-checked
  source once, and accepts only strict installed/no-change evidence with
  Docker disabled/inactive, listen policy `not-started`, and no Docker
  installation/image pull, Compose/auth/targets, containers/service starts,
  public binds, Manager registration, Scylla start, or secrets. Any uncertain
  started outcome is manual-recovery/no-retry; exact pre-invocation prepared
  recovery and zero-process/zero-write success re-entry are preserved. The
  VERIFY journal, authorization, post-Manager reconciliation, and plans remain
  unchanged, local `show` validates but does not project the two redacted
  companions, and no CLI/public wiring or upstream workaround is added.
  The internal `reconcile_deploy_monitoring_stack_result` continuation now
  reloads that exact terminal-success chain and persists a separate immutable
  post-monitoring reconciliation. It requires the canonical target's strict
  Scylla Monitoring 4.16.0 installed/no-change evidence, disabled/inactive
  Docker, listen policy `not-started`, exact archive/component/source/command
  provenance, and no Docker/image-pull/Compose/auth/target/container/start/
  public-bind/Manager/Scylla/secret action. It marks only mapped
  `monitoring-stack` evidence-bound succeeded, proves the historical
  21-position mapping unchanged, and evaluates only the immediate next active
  gate from current canonical evidence. A ready mutating gate becomes only
  `evidence-ready-authorization-required`; no target/auth/Compose generation,
  stack health/readiness/listener inference, process call, authorization, or
  public wiring occurs. Exact reuse is zero-write, conflicts fail closed,
  local `show` validates the bounded redacted record, and the VERIFY journal
  and all prior artifacts remain unchanged.
  The internal `authorize_deploy_manager_agent` continuation accepts only an
  ordinary normalized approval under the same held deploy lock. It derives the
  complete canonical Scylla stable-ID set for exact mapped position 16, current
  Ubuntu 24.04 architecture and successful Scylla-install evidence, and the
  Manager 3.12 agent package/repository/signing-key/source/command intent from
  canonical state. Interactive or PLAN-permitted `cli-yes` approval is
  required; destructive and narrow proofs are refused. The immutable
  owner-only authorization remains unconsumed with execution unavailable,
  contains only bounded identifiers and digests, is validated by local `show`,
  and does not run Ansible, configure a token, start a service, alter the
  VERIFY journal, or add CLI/public wiring.
  The
  functional `show` subset
  reads validated local metadata, desired
  state, operation journals, and any already-persisted strict
  observation/inventory/trust records. External refresh, live SSH checks, and
  operation orchestration remain unavailable.
  Config/desired schema v2 now records explicit image filters and managed-network
  CIDRs. Packaged `oci-root/v3` consumes that exact generated tfvars shape and
  performs provider-schema-validated, shape-filtered AVAILABLE image discovery,
  unique-newest selection, and review-evidence output. It also defines managed
  VCN/private subnet/NAT routing, optional public jump subnet/internet routing,
  existing-network non-ownership, and role NSGs with operator-to-jump SSH,
  jump-to-private SSH, Scylla internode, Manager-agent/CQL, and monitoring scrape
  relationships. Stable-ID instances, role data volumes/attachments, explicit
  retained-volume destruction prevention, provisional local-NVMe capability
  evidence, and the complete strict host manifest are included. No guessed
  guest device path is emitted. No CQL client CIDR ingress is configured because schema v2 has
  no client-ingress selector. Existing-network route/gateway/subnet suitability
  remains a later preflight fact, not a Terraform claim. Compiling provider-derived zone/rack defaults
  into `ClusterSpec` requires canonical zone identities supplied by a future
  provider adapter; the local compiler never claims configured aliases are
  provider facts.
- Python 3.11 and newer, stable Terraform CLI `>=1.5.0,<2.0.0`, and stable
  ansible-core `>=2.17.0,<2.21.0` are supported
  by the implemented boundaries. The partial OCI source constrains provider
  `~>9.1.0` and packages a Terraform-generated lock selecting 9.1.0. The
  guest matrix is Ubuntu 24.04 on `amd64`/`x86_64` and `aarch64`. The initial
  ScyllaDB release line is 2026.2 and requires an exact package version.
  The Manager agent install slice pins Manager 3.12, the current stable line
  documented as compatible with ScyllaDB 2026.2; monitoring version matrices
  and Manager server/backend registration remain unselected.
- OCI auth workflows, replication policy, backup policy, Terraform backend
  orchestration, and distribution model require
  explicit decisions listed in `PLAN.md`.
- AWS and GCP are architectural extension points only, not supported providers.
- No real infrastructure validation has been performed.

## Documentation to consult during implementation

Project-specific sources:

- [OCI provider for Terraform](https://registry.terraform.io/providers/oracle/oci/latest/docs)
- [ScyllaDB Ansible integration](https://docs.scylladb.com/manual/stable/using-scylla/integrations/integration-ansible.html)
- [ScyllaDB Ansible roles](https://github.com/scylladb/scylla-ansible-roles)
- [ScyllaDB Ansible roles wiki](https://github.com/scylladb/scylla-ansible-roles/wiki)
- [ScyllaDB 2026.2 Linux package installation](https://docs.scylladb.com/manual/branch-2026.2/getting-started/install-scylla/install-on-linux.html)
- [ScyllaDB OS support by version](https://docs.scylladb.com/stable/versioning/os-support-per-version.html)
- [OCI Ubuntu 24.04 platform images](https://docs.oracle.com/en-us/iaas/images/ubuntu-2404/index.htm)

Other authoritative roots and guides:

- [Terraform state](https://developer.hashicorp.com/terraform/language/state),
  [backends](https://developer.hashicorp.com/terraform/language/backend), and
  [JSON format](https://developer.hashicorp.com/terraform/internals/json-format)
- [Ansible inventory guide](https://docs.ansible.com/ansible/latest/inventory_guide/index.html)
  and [inventory plugin development](https://docs.ansible.com/ansible/latest/dev_guide/developing_inventory.html)
- [OCI documentation](https://docs.oracle.com/en-us/iaas/Content/home.htm)
- [ScyllaDB documentation](https://docs.scylladb.com/manual/stable/),
  [Manager](https://manager.docs.scylladb.com/stable/), and
  [Monitoring](https://monitoring.docs.scylladb.com/stable/)
- [Python documentation](https://docs.python.org/3/),
  [Python Packaging User Guide](https://packaging.python.org/),
  [OWASP Secrets Management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html),
  and the [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)

See `PLAN.md` for the detailed resource list and implementation acceptance
criteria.
