# Release Notes

## 26.9.1

Initial planning and documentation scaffold:

- added a comprehensive implementation plan for the proposed
  `deploy_scylla_vms.py` CLI, OCI/Terraform provisioning, Ansible orchestration,
  cluster lifecycle safety, state/inventory reconciliation, testing, and phased
  delivery;
- added contribution guidance for future coding agents;
- documented the project's intended capabilities, security principles,
  limitations, and authoritative implementation resources;
- added Python, Terraform, Ansible, generated-state, secret, and editor ignore
  rules; and
- added the MIT License and initial version metadata;
- added an installable Python 3.11+ package, thin source entry point, console
  script, and truthful help/version output;
- registered all 12 planned operations and the OCI-only provider behind typed,
  immutable foundation models;
- implemented the exact shared-group and operation-specific argparse allowlists
  for all 12 operations, including strict scalar/list/map parsing and locally
  decidable required-together, mutual-exclusion, conditional, and narrow
  acknowledgement rules;
- added typed immutable operation requests with explicit unset, default,
  derived, persisted-baseline, empty-list, and numeric-zero distinctions;
- implemented strict operation-aware non-secret environment resolution and
  typed, redacted environment-only protected-input intake, including OCI
  authentication-mode and SSH/repository required-together checks;
- implemented strict common provider/cluster/state-root precedence and
  non-mutating canonical state-layout validation, including traversal, symlink,
  ownership, and permission refusal;
- added explicit canonical state initialization with exact owner-only modes,
  POSIX no-follow race defenses, strict path/type/hard-link validation, and
  local unexpected Terraform state/backend metadata refusal;
- added bounded POSIX per-cluster locking with redacted owner diagnostics and
  no automatic stale-lock breaking;
- added strict `deploy-scylla-vms.cluster/v1` identity/provenance and
  `deploy-scylla-vms.operation/v1` journal/checkpoint envelopes with
  identity/generation/digest and transition validation;
- added deterministic UTF-8 JSON persistence with restrictive sibling
  temporaries, file and directory fsync, atomic replacement, lost-update
  guards, and failure cleanup;
- finalized strict read-only `deploy-scylla-vms.config/v1` TOML defaults with
   canonical path/type/ownership/link/permission checks, native-type and exact
   field validation, secret/interpolation/include refusal, and
   CLI-over-environment-over-config precedence;
- added immutable `deploy-scylla-vms.desired/v1` cluster specifications for
   canonical zones/racks, stable initial logical IDs, role placement/shapes,
   private network and SSH references, and role-restricted storage policies,
   with deterministic round trips, digests, provenance, and proposed-change
   comparison against a persisted baseline;
- upgraded `cluster.json` to `deploy-scylla-vms.cluster/v2` so the complete
   desired specification is identity-bound and can be explicitly updated only
   with generation/digest guards, including a matching-held-lock API;
- implemented the first functional operation: local-only `show` now reads
  canonical schema-v2 metadata, desired state, and validated latest operation
  journals under a non-mutating exclusive read lock;
- added deterministic human output and the independent
  `deploy-scylla-vms.show/v1` JSON envelope with section/stable-ID filters,
  allowlisted desired topology/network/storage/provenance projection, explicit
  freshness/unknown findings, address omission, and post-render `--fail-on`
  handling;
- made every `show --live` source an explicit not-implemented refusal and marked
  Terraform output, inventory, provider, connectivity, health, and exact address
  evidence unavailable or not performed rather than fabricating observations;
- added a generic controlled external-process runner with canonical executable
  and working-directory validation, argument-array/no-shell launch, minimal
  allowlisted child environments, owner-only umask, strict UTF-8, active
  timeout/output bounds, protected-value/path redaction, and stable typed
  failures;
- established the stable Terraform CLI `>=1.5.0,<2.0.0` contract through strict
  `terraform version -json` parsing, including malformed, duplicate,
  prerelease, unsupported, and oversized-output refusal;
- added fully anchored internal Terraform version/init/fmt-check/validate/
  detailed-plan/saved-plan-show/output builders and a matching-lock execution
  service, with explicit work/data/plugin-cache/backend/state/plan paths,
  Terraform locking, detailed exit-code handling, and pre-init unexpected-state
  refusal;
- added independent strict v1 Terraform output, host-manifest, and
  storage-manifest schemas with bounded JSON parsing, exact fields, canonical
  identity/address/topology checks, deterministic ordering, role/storage/device
  combination validation, desired-state comparison, secret-like material
  refusal, and opt-in address projection;
- added strict `deploy-scylla-vms.observed/v1` Terraform-observation persistence
  at the canonical cluster Terraform path, with allowlisted complete manifest
  round trips, injected capture timestamps, source/schema/identity binding,
  generation and digest guards, owner-only atomic writes, and matching-lock
  enforcement;
- added immutable deterministic desired/observed reconciliation for membership,
  stable identity, role/zone/datacenter/rack, shape, routing, provider identity,
  and storage policy/ownership facts, including distinct match, intended-change,
  drift, unknown, and sensitive-conflict classifications;
- added deterministic JSON-compatible static Ansible inventory with stable
  logical host keys, role/zone/datacenter/rack groups, collision refusal,
  allowlisted hostvars, structured direct/ProxyJump routing, mandatory host-key
  checking, and explicit unresolved-trust readiness;
- added strict generation/digest-bound inventory persistence and a local refresh
  service that compares candidate membership/identity/address/topology/routing/
  storage changes, detects stale source manifests, and requires explicit caller
  approval under the matching cluster lock;
- extended local-only `show` to validate and project any persisted observation
  and inventory, report local provenance/freshness/reconciliation, omit exact
  addresses by default, disclose them only with `--include-addresses`, and apply
  local drift/conflict/unknown failure semantics without network access or
  writes;
- added a provider-neutral Terraform-input adapter protocol with exactly one
  offline OCI implementation, consuming explicit image/zone/shape/local-NVMe
  capability facts without making account or capacity claims;
- added strict deterministic `deploy-scylla-vms.terraform-input.oci/v1` and
  `deploy-scylla-vms.tfvars/v1` contracts for stable hosts, placement, ownership
  tags, managed/existing network intent, explicit ingress CIDRs, storage backend
  selection, and public SSH bootstrap material, with secret/unknown/invalid
  combination refusal and matching-lock generation/digest persistence;
- added strict owner/link/permission/size/OpenSSH validation for configured
  public-key files, including decoded key-algorithm checks and private-key
  refusal;
- added immutable approved Terraform source-bundle and
  `deploy-scylla-vms.terraform-source/v1` staging-record contracts with
  deterministic file hashes, canonical work-tree staging, tfvars preservation,
  idempotence, downgrade/tamper/unexpected-file/active-state refusal, and
  rollback after failed record replacement;
- added optional command-to-staged-source digest binding and planning refusal
  for bundles explicitly marked not planning-ready;
- advanced strict TOML and desired-state contracts to
  `deploy-scylla-vms.config/v2` and `deploy-scylla-vms.desired/v2`, requiring
  explicit per-deployed-role OCI image OS/version filters and explicit
  managed-network VCN/per-zone subnet CIDRs while rejecting incompatible v1
  records;
- advanced the OCI provider-input contract to
  `deploy-scylla-vms.terraform-input.oci/v2` for per-role filters, managed
  subnet keys/CIDRs, and selected image evidence;
- added deterministic offline OCI image selection from caller-supplied AVAILABLE
  image/shape/architecture facts, including no-match and tied-newest refusal and
  selected image identity/name/time evidence in generated host inputs;
- added RFC 1918 containment, prefix, zone-completeness, uniqueness, and
  non-overlap checks for managed network CIDRs plus explicit jump-host-only
  public subnet/IP policy;
- added packaged, deterministic `oci-root/v1` Terraform source with exact
  schema-v2 provider-input types, identity/network invariants, and no
  infrastructure resources;
- added shape-filtered `oci_core_images` lookups with explicit OS/version
  matching, unique-newest AVAILABLE selection checks, generated-evidence
  consistency checks, stable logical-host image review outputs, and a strict
  matching Python output parser;
- constrained OCI provider to `~>9.1.0`, packaged the Terraform-generated lock
  selecting 9.1.0, and added source/package/hash/staging/static contract tests;
- advanced the immutable packaged source to `oci-root/v2` with managed VCN,
  regional private subnet, NAT/private-route, optional public jump-subnet/
  Internet-route, and existing-network non-ownership branches;
- placed the one active packaged OCI root at stable physical path
  `scylla_vms/terraform/bundles/oci_root/`, while retaining `oci-root/v2` as the
  persisted logical immutable identity bound to exact source hashes;
- added role NSGs with bounded operator-to-jump SSH, NSG-referenced
  jump-to-private SSH, Scylla internode, Manager-agent/CQL, and monitoring scrape
  ingress plus intentional stateful outbound access, without public database or
  service ingress;
- added strict versioned intermediate network evidence and Python parsing for
  VCN/subnet/NSG identities, ownership, mode, and unvalidated external-routing
  status;
- advanced the immutable source to planning-ready `oci-root/v3` with stable
  logical-ID compute instances, private/public VNIC policy, reviewed images,
  deterministic ownership tags, SSH bootstrap metadata, and explicit boot
  volume termination behavior;
- added role-specific OCI Block Volumes and attachments, static retained-volume
  destruction prevention, local-NVMe capability branches, CHAP refusal, and
  provisional storage evidence without fabricated guest device paths;
- added complete strict host/storage/image/network Terraform output, including
  deterministic routing and parser cross-checks across membership, identity,
  roles, and NSG coverage;
- established stable ansible-core `>=2.17.0,<2.21.0`, ansible-lint `>=25,<27`,
  and yamllint `>=1.35,<2` controller/development constraints, requiring
  ansible-core 2.20+ in Python 3.14 development environments;
- added strict dual Ansible executable version probes, controlled inventory and
  playbook command builders, exact minimal environments, bounded execution, and
  owner-only ephemeral non-secret extra-vars files with unconditional cleanup;
- added an integrity-checked packaged `ansible.cfg` whose inventory, controller
  home/temp/cache/control, SSH config, and log paths are anchored below canonical
  cluster state, with host-key checking required and retry files disabled;
- registered all 28 PLAN playbook names and exact operation mappings with
  classifications, target/limit policy, check/diff/tag/variable allowlists,
  inventory/host-key/health gates, and stable unavailable-source refusal;
- added `deploy-scylla-vms.ssh-trust/v1` owner-only atomic persistence bound to
  cluster identity, exact observation/inventory generations and digests, stable
  logical/provider IDs, canonical endpoint/port, jump route, confirmation
  provenance, timestamps, generation, and key-entry digest;
- added strict Ed25519 and NIST P-256 ECDSA SSH wire-key validation, OpenSSH
  SHA-256 fingerprints, candidate-only direct `ssh-keyscan`, local
  `ssh-keygen -F` inspection, explicit confirmation/expected-fingerprint
  promotion, and changed-key replacement-workflow refusal;
- added deterministic owner-only `known_hosts` and typed SSH configuration with
  host-key checking on every hop, plus zero/one/multiple-jump routing validation
  matching Terraform's sorted-stable-ID SHA-256 selection policy;
- added exact `ansible-inventory --list`/`--graph` validation for hosts, groups,
  hostvars, source metadata, routes, aliases, and secret-like keys, with
  immutable `deploy-scylla-vms.ansible-readiness/v1` operation-class blockers;
- made production Ansible execution require a current readiness report bound to
  the exact inventory while keeping syntax/local fixture checks exempt, and
  extended local `show` with redacted trust fingerprints, route status, and
  readiness without network access or writes;
- deliberately refused private-through-jump key scanning because portable
  `ssh-keyscan` has no safe ProxyJump interface; bootstrap requires confirmed
  jump trust followed by independently verified private-host candidates;
- added the dependency-free production `inventory-preflight` playbook with
  controller-only, check-mode-safe validation of stable identity, role, zone,
  provider identity, topology nullability, inventory/observation provenance,
  explicit target membership, and secret-like inventory refusal;
- added the production `connectivity-check` playbook with bounded batches of
  explicitly limited hosts, mandatory host-key/trust/route gates, read-only
  Ansible ping checks, and strict redacted success/partial-failure/timeout
  handling;
- corrected generated inventory v1 serialization to canonical static
  JSON-compatible YAML accepted by Ansible while preserving separate exact
  `ansible-inventory --list` evidence normalization;
- marked those initial two production catalog entries source-available, then
  added `evidence-collect` as the third reviewed source;
- implemented the guarded read-only `check-jump-hosts` CLI workflow with strict
  canonical local-state reconciliation, non-mutating locking, exact stable
  jump-ID selection, preflight-before-connectivity ordering, bounded connection
  and aggregate timeouts, mandatory trust/route/host-key gates, and no
  Terraform, provider, journal, or canonical-state writes;
- added deterministic redacted human output and independent
  initial `deploy-scylla-vms.check-jump-hosts/v1` JSON output with provenance
  (superseded by v2 below),
  performed/not-performed checks, route/trust summaries, per-jump status, and
  rendered partial/full/timeout/invalid-evidence exit `7` results;
- added strict `ROLE=PORT` destination TCP probes for allowlisted Scylla,
  Manager, and monitoring service ports, resolving only bounded RFC 1918 targets
  assigned to selected jumps and using read-only `ansible.builtin.wait_for`;
- added redacted per-jump/destination passed, failed, and not-performed evidence,
  deterministic representative/all-target selection, aggregate deadlines, and
  the versioned `deploy-scylla-vms.check-jump-hosts/v2` output; arbitrary
  names/addresses/protocols/ports and private-target SSH remain unavailable;
- added the third reviewed production Ansible source, `evidence-collect`, with
  explicit stable-ID limits, serial-five read-only collection, bounded fact and
  argv-form service/Scylla checks, and a strict allowlisted per-host
  `deploy-scylla-vms.ansible-host-evidence/v1` parser that preserves partial,
  unavailable, and not-performed results without retaining raw stdout;
- added optional `deploy-scylla-vms.diagnostics-evidence/v1` persistence at
  `<cluster-root>/logs/evidence.json`, separated from collection and guarded by
  explicit approval, matching lock, current observation/inventory/trust
  provenance, generation/digest checks, and owner-only atomic replacement;
- added the production `base-os` source and role for the exact initial matrix of
  Ubuntu 24.04 on OCI `amd64`/guest `x86_64` and OCI/guest `aarch64`, with
  gathered-fact/image-evidence matching, serial-one stable-ID execution,
  check/diff preview, generic APT prerequisite and `systemd-timesyncd`
  convergence, fixed
  reboot-required detection without reboot, and strict redacted changed/
  no-change/reboot-required/unsupported/failure evidence;
- marked only `base-os` newly source-available while retaining refusal for the
  other 24 unreviewed playbooks; no ScyllaDB repository/package, storage/tuning,
  security-control weakening, or public operation wiring was added;
- added the fifth reviewed production Ansible source, Scylla-only
  `storage-discover`, with serial-five stable-ID limits, check-mode-safe
  read-only block/NVMe discovery, explicit optional-tool availability, and
  strict `deploy-scylla-vms.ansible-storage-discovery/v1` evidence bound to
  observation, inventory, host-manifest, and storage-policy provenance;
- kept serial/WWN/provider attachment identifiers internal and added strict
  topology, duplicate, path, size, signature, secret-like, malformed, and
  identity-conflict refusal without adding storage preflight, persistence,
  preparation, device mutation, or public operation wiring;
- added the sixth reviewed production Ansible source, Scylla-only
  `storage-preflight`, with exact persisted desired-policy, Terraform-manifest,
  inventory, trust, and discovery provenance gates; deterministic block-volume
  and local-NVMe selection; root/boot, active-use, unknown-tool, stale-marker,
  identity, capacity, and backend drift refusal; clean-new, exactly owned
  no-op, and separately reviewed wipe-required classification; hashed public
  device identities; and a provenance-bound preparation-intent digest;
- kept storage preflight return-only and check-mode-safe: its packaged
  controller projection does not access, open, wipe, format, partition,
  assemble, mount, activate, or persist device state, and `storage-prepare`
  remained unavailable at that slice;
- added the seventh reviewed production Ansible source, Scylla-only
  `storage-prepare`, with exactly one stable-ID target, serial-one fatal
  scheduling, gathered facts, privilege escalation, explicit tags, and strict
  check-mode refusal;
- bound its owner-only typed runtime intent to the current cluster/node/provider,
  storage policy, observation, inventory, discovery, preparation-intent,
  operation ID, and exact device-set digest; rejected stale/tampered preflight,
  blocked classification, changed device evidence, symlinks, extra/missing
  devices, and mismatched approvals before writing;
- required separate digest-bound acknowledgement for reviewed wipes, preserved
  `owned-noop` without rewriting, and implemented only fixed XFS single-device
  or exact-set RAID0 preparation at `/var/lib/scylla`, with UUID fstab/mount and
  an atomic owner marker after successful mount;
- added strict `deploy-scylla-vms.ansible-storage-prepare/v1` evidence for
  changed/no-op/not-predicted/failed outcomes, hashed device/filesystem/marker
  identities, completed steps, first irreversible action, post-action
  verification, and honest manual-recovery semantics; this code has fake/static
  coverage only, has not touched real devices, and remains unavailable through
  public operation orchestration;
- added the eighth reviewed production Ansible source, Scylla-only
  `storage-postcheck`, with exactly one stable-ID target, serial-one fatal
  scheduling, gathered facts, privilege escalation for read-only metadata,
  explicit tags, and full check-mode safety;
- bound postcheck execution to current lock/readiness/trust/inventory and exact
  desired/Terraform/discovery/preflight/preparation provenance, with fail-closed
  verification of device identities/membership, RAID0, XFS/UUID, fstab, mount,
  capacity, permissions, holders/signatures, and the atomic ownership marker;
- added strict
  `deploy-scylla-vms.ansible-storage-postcheck/v1` evidence containing only
  deterministic passed/failed/unknown checks, bounded redacted blockers,
  provenance digests, hashed device identifiers, and readiness for the future
  Scylla installation slice; no repair, remount, write, Scylla installation,
  public operation wiring, or real-device execution was added;
- corrected the unsupported guest baseline to the explicit user-selected
  Ubuntu 24.04 matrix on OCI `amd64`/guest `x86_64` and OCI/guest `aarch64`;
  new desired state refuses Oracle Linux and all other OS values without
  silently migrating persisted desired records;
- selected ScyllaDB release line 2026.2 and added the packaged, hash-checked
  `scylla-install` candidate, requiring an exact patch/package version, current
  base-OS/storage evidence, exact provenance, one Scylla stable ID, and
  masked/inactive `scylla-server`;
- pinned the official signed repository definition, vendored 2026 signing-key
  artifact and full fingerprint, exact seven-package set, TLS/signature verification,
  and package-script startup refusal, with strict
  `deploy-scylla-vms.ansible-scylla-install/v1` evidence;
- pinned `scylladb/scylla-ansible-roles` commit
  `42592128ff0399be8ffa18dbc985c4b026e7abd0` for future configuration but kept
  installation wrapper-owned because that role snapshot's Ubuntu path uses
  broader repository, shell, Java, and package-removal behavior; no real host
  or package installation was performed; authenticated the complete key against
  the official 2026.2 signed `InRelease` fingerprint and immutable official
  key-ID references, recorded retrieval and verification provenance, added
  digest/fingerprint/tamper refusal, and marked `scylla-install`
  source-available without adding host-side key download;
- added `scylla-configure` as the tenth source-available production Ansible
  entry and the 31st catalog entry, using wrapper-owned exact templates because
  the pinned upstream role cannot be safely constrained to configuration-only
  behavior;
- bound configuration to current base-OS, storage-postcheck, install,
  observation, inventory, trust, desired-spec, Ubuntu 24.04, architecture, and
  exact ScyllaDB 2026.2 package evidence; added normalized immutable
  cluster/datacenter/rack checks, RFC 1918 and duplicate-address refusal, fixed
  storage directories, and deterministic one-to-three stable-ID seed policy
  with healthy-survivor requirements for add/replace;
- atomically manages only exact allowlisted `scylla.yaml` and
  `cassandra-rackdc.properties` content as root-owned mode `0644`, keeping
  `scylla-server` masked/inactive before and after without package, storage,
  tuning, firewall, SSH, Manager, start, bootstrap, or health behavior;
- added strict `deploy-scylla-vms.ansible-scylla-configure/v1` changed/no-op/
  not-predicted/failed evidence with configuration/topology/seed and
  prerequisite digests, installed version, service state, redacted blockers,
  and truthful `runtime_validation_performed=false`;
- added `scylla-bootstrap` as the eleventh source-available production Ansible
  entry with exact-one-target, serial-one, fatal scheduling and explicit
  `initial-seed` and `join-existing` modes rather than node-count inference;
- bound first start to reviewed operation/node/spec/observation/inventory/trust/
  storage/install/configuration/topology/seed evidence, requiring an empty new
  cluster for initial seed or healthy surviving members/seeds, target absence,
  capacity/topology/schema gates, and exact add/scale intent for a join;
- revalidates immediately before a systemd-only unmask/start boundary, then
  waits boundedly for local CQL and argv-form `nodetool` Up Normal, exact
  datacenter/rack, self-consistent Host ID, completed streaming, and schema
  agreement evidence without shell execution;
- added strict address-free
  `deploy-scylla-vms.ansible-scylla-bootstrap/v1` success/failure evidence with
  hashed ring/Host-ID values and explicit membership-may-have-changed recovery
  boundaries; failures are never destroyed or retried automatically and are
  remasked only when the node is proven never joined;
- added `scylla-health` as the twelfth source-available production Ansible
  entry: a read-only, check-mode-safe, serial-five full-cluster health source
  using fixed argv-form `nodetool info`, `status`, `describecluster`, and
  `netstats`, read-only service state, and bounded local API/CQL reachability;
- added strict `deploy-scylla-vms.ansible-scylla-health/v1` reconciliation of
  stable logical IDs, local Host IDs, provider-identity digests, every
  normalized ring view, datacenter/rack, Up Normal state, schema agreement,
  streaming inactivity, storage readiness/capacity, timestamps, and current
  observation/inventory/trust/storage provenance without addresses or raw
  command output;
- made missing, extra, duplicate, joining/leaving/moving/down, inconsistent,
  topologically stale, schema-disagreeing, streaming, service/API/CQL, and
  storage failures explicit blockers, while unauthenticated replication,
  quorum, and Manager backup checks remain unknown/not performed and block
  stronger operation classes; one-coordinator execution requires a complete
  prior stable-ID/Host-ID map, and `show --live` remains unavailable;
- added `scylla-remove-live` as the thirteenth source-available production
  Ansible entry with exact-one-target, serial-one, fatal scheduling, gathered
  facts, privilege escalation, explicit tags, and hard check-mode refusal;
- required fresh full-cluster health plus independent passed replication,
  quorum, post-removal capacity, and backup-policy evidence, and bound narrow
  destructive authorization to exact cluster/operation, stable/Host/provider
  identity, datacenter/rack, desired removal intent, current provenance, health
  generation/digest, and intended post-removal topology;
- revalidated target identity from both the target and a healthy survivor
  immediately before exact argv-form `nodetool decommission`, then added bounded
  survivor polling for target absence, Up Normal survivors, schema agreement,
  idle streaming, and exact topology without raw output, addresses, or secrets;
- added strict
  `deploy-scylla-vms.ansible-scylla-remove-live/v1` result and operation
  checkpoint projections that preserve command-start/completion and membership
  mutation boundaries, require reviewed recovery after interruption/failure,
  and prohibit blind decommission retry; no VM stop/deletion, storage wipe,
  desired-state edit, Terraform action, dead-node removal, or CLI operation was
  added;
- added `scylla-remove-dead` as the fourteenth source-available production
  Ansible entry, limited to one explicitly selected healthy surviving
  coordinator and never the unavailable target, with independent target
  unreachability, unchanged stable/Host/provider identity, consistent survivor
  ring views, fresh survivor health/schema/streaming evidence, all-passed
  replication/quorum/capacity/backup gates, and exact intended post-topology;
- bound its narrow destructive authorization to cluster, operation, dead target,
  coordinator, health, observation, inventory, trust, and post-topology
  identities; immediately revalidated the required survivor quorum; and used
  only argv-form `nodetool removenode <host-id>` plus supported status/read
  commands, with no automatic force completion, target contact, infrastructure,
  storage, desired-state, provider, or Terraform mutation;
- added strict `deploy-scylla-vms.ansible-scylla-remove-dead/v1` redacted
  results and checkpoint evidence for exact target/coordinator identities,
  hashed Host IDs, pre/post digests, removal and mutation boundaries,
  postconditions, and recovery-required failures that prohibit blind retry;
- added `scylla-replace-dead` as the fifteenth source-available production
  Ansible entry, limited to one newly provisioned replacement stable logical
  target with a distinct provider identity, quorum-consistent DN old Host-ID
  evidence, independent old-target unreachability, fresh empty storage, exact
  ScyllaDB 2026.2 patch/config/topology/seeds, and passed replication/quorum/
  capacity/backup gates;
- bound narrow replacement authorization to the exact operation, stable ID,
  old Host/provider identity, new provider identity, observation, inventory,
  trust, storage, configuration, survivor health, topology, and intended
  post-state, while refusing active topology work and any prior `removenode`;
- immediately revalidated survivor and replacement state, atomically added only
  `replace_node_first_boot: <dead-host-id>` while `scylla-server` remained
  masked/inactive, crossed one systemd unmask/start boundary, and used bounded
  argv-form `nodetool gossipinfo`, `status`, `describecluster`, and `netstats`
  checks to prove a new UN Host ID, old Host-ID absence, schema agreement, idle
  streaming, and exact topology without IP-based identity;
- added strict `deploy-scylla-vms.ansible-scylla-replace-dead/v1` redacted
  results and checkpoints with hashed old/new Host and provider identities,
  pre/post/prerequisite digests, retained-key truth, repair/RBNO status,
  mutation boundaries, and conservative recovery. This slice never runs
  `removenode`, force, repair, destroy, wipe, Terraform, or cloud operations;
  later repair/Manager evidence remains mandatory unless complete enabled RBNO
  evidence proves repair unnecessary;
- added `scylla-repair` as the sixteenth source-available production Ansible
  entry, restricted to one exact stable-ID target and the explicit
  post-replacement or operator-reviewed post-bootstrap reasons;
- required current full-cluster UN/topology/schema/streaming evidence, exact
  target Host ID/DC/rack/2026.2 version, current observation/inventory/trust/
  config/storage and source-result bindings, passed capacity/quorum checks, no
  competing operation, and narrow digest-bound repair authorization;
- added strict RBNO-enabled-and-complete replacement no-op handling without
  inferring RBNO from version, plus immediate fixed-command revalidation,
  foreground argv-form `nodetool repair`, and post-health/pending-repair/
  compaction verification with no shell, selector flags, or automatic retry;
- added strict `deploy-scylla-vms.ansible-scylla-repair/v1` redacted evidence
  and checkpoints for reason/status, RBNO skip, hashed Host ID, pre/post/source
  digests, operational-versus-cryptographic completion truth, mutation
  boundary, review requirement, and recovery after timeout/interruption;
- added `scylla-cleanup` as the seventeenth source-available production Ansible
  entry, restricted to one exact Python-authorized eligible stable ID after a
  completed healthy add-node or scale-out topology change;
- required exact post-expansion topology, fresh full-cluster UN/schema/streaming
  health, sufficient disk/compaction headroom, current observation/inventory/
  trust/config/storage evidence, required completed repair/RBNO evidence, no
  competing operation, and narrow digest-bound authorization;
- added immediate fixed-command revalidation, the sole foreground argv-form
  `nodetool cleanup` mutation, and bounded compaction/pending-work/full-health
  polling with no shell, selector options, parallel nodes, or automatic retry;
- added strict `deploy-scylla-vms.ansible-scylla-cleanup/v1` redacted evidence
  and checkpoints for target/hashed Host ID, source topology-change and repair
  digests, pre/post health, command/pending-work and mutation boundaries, and
  recovery after timeout, interruption, command, pending-work, or health
  failure;
- added `jump-host-configure` as the eighteenth source-available production
  Ansible entry, restricted to one exact Python-authorized jump stable ID after
  current Ubuntu `base-os` evidence, complete trust, and inventory-derived
  ProxyJump routes;
- required password/root login disabled, public-key-only authentication, local
  TCP forwarding, `PermitOpen` from exact RFC 1918 private host:22 routes or
  `none`, inventory `AllowUsers`, and refusal of agent/X11/tunnel/stream-local
  forwarding, remote forwarding, `PermitOpen any`, and host-key bypass;
- added argv-form `ssh-keygen -l`/`sshd -t` validation, atomic drop-in install
  at `/etc/ssh/sshd_config.d/00-deploy-scylla-vms.conf` with restore on failure,
  and Ubuntu `ssh` reload only after a successful change;
- added strict `deploy-scylla-vms.ansible-jump-host-configure/v1` redacted
  evidence for changed/noop/not-predicted/failed status, config/route/host-key/
  provenance digests, validation/reload truth, and bounded blockers;
- added `manager-agent` as the nineteenth source-available production Ansible
  entry, restricted to one exact Ubuntu 24.04 Scylla stable ID after current
  successful `base-os` and `scylla-install` evidence;
- pinned official Manager 3.12 as the ScyllaDB 2026.2-compatible agent line,
  reused the authenticated 2026 signing key after verifying it signs the
  official Manager 3.12 InRelease, and installed only exact
  `scylla-manager-agent` versions;
- left configuration, `auth_token`, helper-slice setup, agent/Scylla startup,
  and server-to-agent reachability explicitly unperformed;
- added strict `deploy-scylla-vms.ansible-manager-agent/v1` redacted evidence
  for installed/no-change/not-predicted/failed status, package/repository/key
  digests, disabled/inactive service truth, and bounded blockers;
- added `manager-server` as the twentieth source-available production Ansible
  entry, restricted to one exact Ubuntu 24.04 manager stable ID after current
  successful `base-os` evidence;
- pinned official Manager 3.12 `scylla-manager-server` and
  `scylla-manager-client` packages, reused the authenticated 2026 signing key
  and Ubuntu Manager 3.12 repository, and left `scylla-manager`
  masked/inactive;
- left local/remote Scylla backend configuration, `scyllamgr_setup`,
  environment-token registration, task creation, and Manager startup explicitly
  unperformed;
- added strict `deploy-scylla-vms.ansible-manager-server/v1` redacted evidence
  for installed/no-change/not-predicted/failed status, package/repository/key
  digests, masked/inactive service truth, and bounded blockers;
- added `monitoring-agent` as the twenty-first source-available production
  Ansible entry, restricted to one exact Ubuntu 24.04 Scylla stable ID after
  current successful `base-os` and `scylla-install` evidence;
- pinned official ScyllaDB 2026.2 `scylla-node-exporter` from the signed
  Ubuntu Scylla repository, reused the authenticated 2026 signing key, and
  left the unit disabled/inactive with listen policy `not-started`;
- left process-exporter, monitoring-stack install, target generation, Manager
  registration, exporter configuration, public bind, secrets, and Scylla
  startup explicitly unperformed;
- added strict `deploy-scylla-vms.ansible-monitoring-agent/v1` redacted
  evidence for installed/no-change/not-predicted/failed status, package/
  repository/key digests, disabled/inactive service truth, listen policy, and
  bounded blockers;
- added `monitoring-stack` as the twenty-second source-available production
  Ansible entry, restricted to one exact Ubuntu 24.04 monitoring stable ID
  after current successful `base-os` evidence;
- pinned official Scylla Monitoring 4.16.0 from the tagged GitHub archive
  after SHA-256 digest check, verified the tagged Prometheus/Grafana/
  Alertmanager/Loki/Promtail versions and 2026.2 dashboard support, and left
  Docker uninstalled/inactive with listen policy `not-started`;
- left scrape-target generation, Grafana auth, public bind, Compose/image
  pull/container startup, Manager registration, secrets, and Scylla startup
  explicitly unperformed;
- added strict `deploy-scylla-vms.ansible-monitoring-stack/v1` redacted
  evidence for installed/no-change/not-predicted/failed status, artifact
  versions/digest/commit, docker inactive truth, listen policy, documented
  ports, and bounded blockers;
- added `monitoring-targets` as the twenty-third source-available production
  Ansible entry, restricted to one exact Ubuntu 24.04 monitoring stable ID
  after current successful `base-os` and `monitoring-stack` evidence;
- generated official Scylla Monitoring 4.16.0 Prometheus target files from
  RFC 1918 inventory identities (`scylla_servers.yml`, required Manager
  `host:5090`, and official node_exporter/manager-agent reuse files) without
  starting Docker, Prometheus, Grafana, Alertmanager, or node_exporter;
- left live scrape, public bind, Compose/container startup, Grafana auth,
  Manager registration, secrets, and Scylla startup explicitly unperformed;
- added strict `deploy-scylla-vms.ansible-monitoring-targets/v1` redacted
  evidence for generated/no-change/not-predicted/failed status, file-path
  digests, hashed identities, stack/agent-target/inventory provenance, listen
  policy, scrape-readiness, and bounded blockers;
- added `manager-tasks` as the twenty-fourth source-available production
  Ansible entry, restricted to one exact Ubuntu 24.04 manager stable ID
  after current successful `base-os` and install-only `manager-server`
  evidence;
- validated only PLAN `inspect`/`quiesce`/`resume`/`validate` actions for
  official Manager 3.12 backup/repair kinds and left live `sctool` inspect,
  suspend, resume, backup, and repair unperformed because Manager remains
  masked/inactive and unregistered;
- left Manager start/unmask, backend yaml, auth tokens, cluster
  registration, and Scylla startup explicitly unperformed;
- added strict `deploy-scylla-vms.ansible-manager-tasks/v1` redacted
  evidence for not-performed/not-predicted/failed status, requested action
  and kinds, `applied=false`, masked/inactive service truth, official
  not-performed command set, and exact inactive/unregistered/backend
  blockers;
- added `storage-retire` as the twenty-fifth source-available production
  Ansible entry, restricted to one exact Scylla stable ID after current owned
  discovery, successful prepare/postcheck, observation/inventory/trust, and
  proven membership absence;
- unmounts `/var/lib/scylla`, removes the UUID fstab entry, and deactivates
  exact RAID0 when present, wipes only `delete` dispositions with separately
  bound wipe consent, and never wipes retained or ephemeral media, runs
  Terraform, destroys VMs, or starts/stops Scylla;
- added strict `deploy-scylla-vms.ansible-storage-retire/v1` redacted
  evidence for changed/no-op/not-predicted/failed status, hashed devices,
  first irreversible step, manual-recovery requirement, provenance digests,
  explicit not-performed Terraform/VM/wipe items, and bounded blockers;
- added `service-converge` as the twenty-sixth source-available production
  Ansible entry, restricted to one Ubuntu 24.04 stable ID after current
  `base-os` and role-appropriate current install evidence;
- reconciled only PLAN-owned systemd units, enabled/started
  `systemd-timesyncd` when that generic unit is in scope, and left
  Scylla, Manager, exporter, and monitoring-stack starts not-performed
  because PLAN does not define a reviewed start allowlist for those
  services;
- added strict `deploy-scylla-vms.ansible-service-converge/v1` redacted
  evidence for converged/no-change/not-predicted/failed status, per-unit
  desired/observed enabled/active state, applied flags, provenance
  digests, explicit not-performed starts, and bounded blockers;
- added `scylla-cluster-shutdown` as the twenty-seventh source-available
  production Ansible entry, restricted to the exact complete Scylla stable-ID
  set after current full-cluster health, observation/inventory/trust, and
  narrow cluster/operation/topology/health authorization;
- refused unreviewed `nodetool drain` and systemd stop/mask because
  PLAN-cited 2026.2 administrator pages do not publish that whole-cluster
  order, required explicit Manager-tasks not-applicable authorization while
  Manager remains unstarted, and never decommissions, wipes storage, or runs
  Terraform;
- added strict `deploy-scylla-vms.ansible-scylla-cluster-shutdown/v1`
  redacted evidence for not-performed/not-predicted/failed status, hashed
  Host IDs, per-node drain/stop/mask states, mutation boundary
  `not-started`, provenance digests, explicit not-performed items, and
  bounded blockers;
- added `os-upgrade-preflight` as the twenty-eighth source-available
  production Ansible entry, restricted to one exact role-aware Ubuntu 24.04
  stable ID with serial-one, fatal, read-only, check-mode-safe execution;
- required current observation/inventory/trust, `base-os`, role package/
  configuration/service/health/route/availability evidence, digest-bound
  operation/space policy, and, for Scylla, complete cross-view health plus
  explicit replication/quorum/capacity/backup/topology rolling gates;
- added bounded checks for `/run/reboot-required`, argv-form `dpkg --audit`,
  fixed package-lock inodes through `/proc/locks`, Linux/architecture, and
  policy-bound root/boot free space without APT refresh or mutation;
- kept every OS path blocked: PLAN defines no target transition beyond the
  Ubuntu 24.04 baseline, exact kernel policy, or read-only package-currency/
  repository proof, so same-release is undefined, every other target is
  unsupported, and provider image facts remain caller-supplied offline
  evidence only;
- added strict `deploy-scylla-vms.ansible-os-upgrade-preflight/v1` redacted
  evidence with transition classification, per-gate status, rolling
  eligibility, provenance digests, explicit not-performed actions, and no
  APT mutation, reboot, service changes, OCI discovery, Terraform, or VM
  replacement;
- added `os-upgrade-in-place` as the twenty-ninth source-available production
  Ansible entry, restricted to one exact role-aware stable ID with serial-one,
  fatal, sensitive, check-mode-refused execution;
- required current execution-successful and explicitly rolling-eligible
  `os-upgrade-preflight/v1`, regenerated observation/inventory/trust/`base-os`
  and role package/configuration/storage/health bindings, and narrow
  operation/node/current-target-OS/architecture/evidence authorization;
- kept every in-place request blocked because no target transition, package
  sequence, role-safe shutdown, or reboot sequence is approved; strict
  `deploy-scylla-vms.ansible-os-upgrade-in-place/v1` evidence reports
  `target-transition-unapproved`, Scylla-specific
  `shutdown-sequence-unreviewed`, mutation boundary `not-started`, all package/
  source/service/reboot/kernel/configuration actions not-performed, no
  automatic retry, and recovery-required false;
- added no APT, package-source, kernel, service, reboot, configuration, storage,
  Terraform, VM, or cloud mutation; source availability means only that the
  executable refusal contract is reviewed and packaged, not that an OS upgrade
  is authorized;
- added `os-reprovision-prepare` as the thirtieth source-available production
  Ansible entry, restricted to one exact role-aware stable ID with serial-one,
  fatal, destructive, check-mode-refused validation-only execution;
- required current exact `os-upgrade-preflight/v1`, observation/inventory/trust/
  `base-os`, role package/configuration/storage/health/lifecycle evidence,
  explicit storage disposition, caller-supplied offline old/new provider-image
  facts, and narrow authorization bound to stable/current-provider identity,
  target transition, topology, and every evidence digest;
- kept every immutable replacement request blocked because no post-24.04 target
  transition or Python/Terraform replacement orchestration is approved, with
  Scylla delegated to reviewed `replace-node` semantics and Manager,
  monitoring, and jump roles retaining explicit restore/re-registration/
  target-refresh/route/retrust blockers;
- added strict
  `deploy-scylla-vms.ansible-os-reprovision-prepare/v1` redacted evidence for
  transition/role classification, provider/image digests, stable/provider
  identity policy, storage disposition, membership/service readiness, mutation
  boundary `not-started`, recovery false, and explicit not-performed provider/
  Terraform/VM/storage/package/service/membership/configuration/reboot actions
  plus automatic retry;
- added no OCI call, Terraform command, VM replacement/destruction, storage
  detach/delete/wipe, desired-state change, service control, Scylla topology
  command, configuration edit, restore/re-registration/retrust, or reboot;
- added `os-upgrade-postcheck` as the thirty-first source-available
  production Ansible catalog entry, with read-only, check-mode-safe,
  exact-one-target, serial-one, fatal execution;
- required exact digest-bound `os-upgrade-in-place/v1` or
  `os-reprovision-prepare/v1` source result/authorization plus current
  observation/inventory/trust, `base-os`, role package/configuration/storage/
  route/service/health evidence and stable/provider/OS/architecture identity;
- kept every current result fail-closed with
  `source-upgrade-not-performed` because both source operations are
  validation-only, never reporting same-version, unsupported, or unapproved
  transitions as successful upgrades;
- added strict `deploy-scylla-vms.ansible-os-upgrade-postcheck/v1` redacted
  evidence for source/result/provenance digests, transition comparison,
  per-gate and performed/not-performed verification, host-state digests, and
  mutation/remediation false, with only bounded OS, architecture, kernel,
  package, reboot-marker, and fixed service-state reads and no APT/package,
  reboot, service/configuration/storage/trust, OCI/Terraform, Scylla, or
  remediation mutation;
- added a strict internal `deploy-scylla-vms.ansible-operation-plan/v1` offline
  resolver that binds the public operation registry to exact conditional catalog
  positions, stable-ID limits, command mode/tag policy, allowlisted variable
  schemas, current inventory/readiness evidence, and pre-health blockers under
  the matching cluster lock;
- added redacted deterministic plan digests and PLAN-phase checkpoint evidence,
  while leaving unimplemented public workflows explicitly blocked and creating
  no runtime variable file, subprocess invocation, journal write, confirmation,
  or operation verification path from the resolver;
- added the independently versioned immutable
  `deploy-scylla-vms.ansible-operation-binding/v1` companion record at the
  canonical operation-journal path, with matching-operation-lock enforcement,
  owner-only atomic persistence, generation/digest guards, and exact
  request/plan/target/catalog/source/readiness/observation/inventory/trust/
  journal bindings;
- added the independently versioned immutable
  `deploy-scylla-vms.ansible-operation-context/v1` companion at
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-context.json`,
  created only after binding and before authorization/execution under the
  matching operation lock, with owner-only no-follow atomic persistence,
  immutable generation/digest guards, and exact request/plan/binding/
  classification/target/safe-intent bindings;
- modeled only the explicit
  `deploy-scylla-vms.ansible-operation-context.check-jump-hosts/v1` allowlist:
  bounded stable-ID selectors, destination/depth enums, unique allowlisted
  role/port checks, and bounded native numeric timeouts; rejected unknown
  fields, aliases, coercions, duplicates, protected inputs, addresses, paths,
  commands, environments, arbitrary variables, and unbounded values;
- preserved binding v1 compatibility and avoided a binding cycle by ordering
  common PLAN journal, binding, context, optional authorization, then execution;
  reconstruction must reproduce the binding request and plan digests while
  address-bearing probes are re-derived from current canonical inventory;
- added strict offline
  initial `deploy-scylla-vms.ansible-operation-resume-validation/v1`
  revalidation (superseded by v2 below) that permits only an unchanged PLAN
  checkpoint and rejects confirmation ambiguity, possible execution,
  destructive boundaries, interruption, failure, completion, stale or drifted
  evidence, malformed/unknown schemas, and missing/conflicting history without
  executing or advancing the journal;
- added immutable
  `deploy-scylla-vms.ansible-operation-authorization/v1` at
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-authorization.json`
  for exact ready non-read-only plans, with matching-operation-lock enforcement,
  owner-only atomic persistence, immutable generation/digest guards, and exact
  operation/cluster/class/target/request/plan/binding/catalog/source/readiness/
  observation/inventory/trust/journal bindings;
- preserved PLAN confirmation semantics through separate normalized proof kinds
  for ordinary approval, destructive class, exact operation scope, storage
  wipe, and monitoring restart; generic `--yes` supplies only ordinary approval,
  read-only operations create no authorization, undefined scope tokens fail
  closed, and no prompt text, entered token, device ID, environment, terminal/
  operator identity, command, arbitrary value, address, key, secret, or
  protected path is persisted;
- advanced the non-durable public resume projection to
  `deploy-scylla-vms.ansible-operation-resume-validation/v2`, requiring exact
  unchanged authorization for non-read-only operations and its absence for
  read-only work while retaining the sole success state
  `resumable-pre-execution`;
- compatibility: internal consumers of resume-validation v1 must accept v2 and
  validate its authorization state/schema/digest fields; there is no persisted
  v1 resume record to migrate, and the v1 common journal and operation-binding
  schemas remain unchanged;
- added the independently versioned redacted
  `deploy-scylla-vms.ansible-operation-preparation-report/v1` and a narrow
  lock-bound internal coordinator that loads current canonical local evidence,
  derives the modeled request context, resolves the exact plan, and invokes the
  existing immutable stores strictly as binding, context, then class-appropriate
  authorization;
- made checkpoint preparation safely restartable only before execution:
  byte-identical records are validated and reused, matching binding-only or
  binding-plus-context prefixes may continue, and any mismatch, journal/history
  drift, execution companion, ambiguous duplicate, forbidden read-only
  authorization, unsafe path, or evidence/source/catalog change fails closed
  without overwrite, deletion, rollback, or common-journal advancement;
- kept preparation internal and subprocess-free: only bounded read-only
  `check-jump-hosts` context is currently modeled, authorization is therefore
  `not-required`, every other operation reports `operation-context-unmodeled`
  before writes, and no prompt, rendering, runner/toolchain call, execution
  record, CLI path, or public mutating workflow was added;
- added the independently versioned
  `deploy-scylla-vms.ansible-operation-execution/v1` companion at
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-execution.json`,
  with canonical-path and matching-operation-lock enforcement, owner-only
  no-follow atomic writes, immutable provenance, append-only attempts, and
  generation/digest transition guards;
- added a narrow injected executor protocol and an internal one-step handoff
  that immediately revalidates request/plan/binding/catalog/source/readiness/
  observation/inventory/trust/journal/authorization, durably records started
  intent before invocation, and consumes exact non-read-only authorization only
  on that first durable attempt;
- bound each attempt to deterministic step/catalog/source/command/variables
  digests and the exact stable-ID limit, accepted only exact per-playbook
  no-output result receipts, and retained bounded `started`, `succeeded`,
  `failed`, `timed-out`,
  `interrupted`, `unreachable`, or `malformed-result` state plus result digest;
  exit zero alone is not success, and every uncertain state requires manual
  recovery review with no automatic retry;
- made pre-execution resume validation v2 refuse whenever the execution
  companion exists, while leaving `deploy-scylla-vms.operation/v1` byte-for-byte
  at its exact `IN_PROGRESS/PLAN` checkpoint for schema compatibility;
- added the strict internal executor adapter from the execution handoff to the
  existing controlled Ansible service, with a typed exact-state context,
  matching-operation-lock and canonical rendered-file checks, current
  inventory/trust/readiness/catalog/source/playbook-hash validation, anchored
  command-intent digest reconstruction, and strict per-playbook result parsing;
- mapped only parsed contract success to `succeeded`, preserving
  failed/unreachable/timeout/interruption/malformed outcomes and treating
  validation-only blocked/not-performed evidence as failure even after exit
  zero; retained no raw output, events, command, variables, environment,
  addresses, keys, or protected paths;
- added a strict inventory-preflight result marker/parser and made every
  packaged playbook preserve bounded exit 2/4 recaps for its result parser;
- kept the adapter internal and fake-process-runner-tested: it is not wired to
  the CLI or public mutating workflows and the adapter tests invoke no real
  Ansible/Terraform process or infrastructure/guest mutation;
- added a narrow internal lock-bound coordinator that derives canonical cluster
  paths, loads strict binding/context/journal/authorization/execution and
  desired/observed/inventory/trust/source/catalog state, reconstructs the exact
  request and allowlisted variables and validates persisted context/plan/binding
  digests before tool probing, validates existing rendered controller artifacts,
  probes the exact sibling Ansible executable pair, and recomputes machine
  readiness plus the bound plan before durable intent;
- constructs the existing controlled executor adapter internally and invokes
  the existing handoff for exactly one deterministic step, retaining the
  established intent-before-effect and manual-recovery/no-retry semantics
  without looping, finalizing, confirming, rendering, post-verifying, or adding
  CLI/public mutating wiring;
- added the independently versioned redacted
  `deploy-scylla-vms.ansible-operation-coordinator-report/v1` projection with
  only operation/attempt/step counts and indices, bounded states, schemas,
  digests, and retry/recovery flags;
- expanded coordinator reconstruction to bounded allowlisted read-only
  `check-jump-hosts` selector/depth/destination/check/timeout combinations and
  added only the context schema/digest to its redacted report; missing legacy
  context and every other operation kind fail before tool probing or durable
  `started`, with unmodeled kinds returning `operation-context-unmodeled` rather
  than accepting caller-supplied paths, plans, commands, variables,
  environments, or executable names;
- added the strict internal
  `deploy-scylla-vms.ansible-check-jump-hosts-orchestration-report/v1` layer,
  accepting only canonical cluster identity, operation UUID, the matching held
  operation lock, and controlled runner/executable dependencies while loading
  its request, plan, steps, and variables exclusively from prepared immutable
  context;
- reconstructed and verified the exact read-only `inventory-preflight` then
  `connectivity-check` plan before tool probing, repeatedly invoked the
  one-step coordinator only for the next durable step, reloaded execution after
  every call, bounded calls by the immutable step count, and allowed only exact
  succeeded-prefix continuation or idempotent complete observation;
- made started, failed, timed-out, interrupted, unreachable, malformed,
  missing, extra, reordered, drifted, and persistence-ambiguous execution stop
  without automatic retry; retained absent authorization and byte-compatible
  `IN_PROGRESS/PLAN` common-journal state for this read-only operation;
- retained `steps-succeeded`/`post-verification-pending` for legacy digest-only
  execution and `execution-stopped`/`not-reached` for uncertain outcomes;
  neither state claims public completion or health, adds CLI wiring, or changes
  the existing public no-write workflow;
- added the independently versioned, owner-only, append-only
  `deploy-scylla-vms.ansible-operation-evidence/v1` companion at
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-evidence.json`
  for the two internal `check-jump-hosts` steps, retaining only exact inventory
  parity/status/counts/provenance and stable-ID connectivity/requested
  role-port TCP outcomes;
- bound each semantic entry to the exact operation, request, plan, binding,
  context, catalog, source, readiness, observation, inventory, trust,
  step/result schema, command, and playbook source, while rejecting unknown,
  duplicate, unrequested, reordered, address-like, key/path/raw-output/
  credential-bearing, malformed, or conflicting evidence;
- persisted semantic evidence after strict result parsing and before returning
  a successful unchanged seven-field executor receipt, made its
  `evidence_digest` the persisted projection digest, and required the execution
  handoff to re-read that exact entry before terminal success; post-effect
  persistence failure and missing/mismatched evidence remain manual-recovery
  and no-retry even though this operation is read-only;
- added strict in-memory reconstruction of the dynamic public-v2 semantic facts
  and advanced the internal orchestrator to
  `steps-succeeded`/`semantic-evidence-ready` only for an exact complete
  companion; legacy digest-only completion remains
  `post-verification-pending`, with no raw-output migration, common-journal
  completion, CLI rewiring, or change to the public write-free workflow;
- added the narrow subprocess-free internal
  `finalize_prepared_check_jump_hosts` post-verification API, accepting only
  canonical cluster identity, operation UUID, and the matching held operation
  lock while loading and revalidating every binding/context/execution/evidence/
  journal/current-local provenance input itself;
- added immutable owner-only
  `deploy-scylla-vms.ansible-operation-finalization/v1` at
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-finalization.json`
  plus its independently versioned address-free report, retaining only bounded
  successful check statuses/counts, stable logical IDs, allowlisted role/port
  pairs, schemas, and provenance/result digests;
- completed the fully verified read-only journal through guarded
  `IN_PROGRESS/PLAN` to `IN_PROGRESS/VERIFY` with `VERIFY/completed` evidence,
  then `SUCCEEDED/JOURNAL`, without changing the common v1 schema; writing the
  companion first permits exact recovery after either journal write fails and
  exact terminal re-entry performs no duplicate write;
- kept failed destination facts and all failed, unreachable, timed-out,
  interrupted, malformed, or started durable attempts in manual-recovery state
  without synthesizing a clean verification failure or automatic retry, and
  kept the finalizer disconnected from CLI/public no-write execution;
- added the internal
  `deploy-scylla-vms.ansible-check-jump-hosts-lifecycle-report/v1` coordinator,
  accepting only canonical cluster identity, operation UUID, an optional typed
  request before durable reconstruction is available, the matching held
  operation lock, and controlled runner/executable dependencies;
- composed the existing checkpoint preparation, deterministic remaining-step
  orchestration, semantic-evidence requirement, and finalizer without
  duplicating their persistence state machines, creating the prerequisite
  common PLAN journal, accepting caller plans/steps/commands/variables/
  environments/evidence, or adding rollback;
- made exact binding/context prefixes, succeeded execution prefixes,
  semantic-evidence-ready execution, companion-only finalization, and VERIFY
  journal prefixes resumable while terminal success performs no write or tool
  call and every uncertain execution remains manual-recovery/no-retry;
- kept this lifecycle fake-only tested and internal, with stable wrong-kind/
  class, missing-prerequisite, forbidden-authorization, and legacy-evidence
  blockers, strict redacted stage/count/schema/digest reporting, no CLI wiring,
  and no change to the existing public write-free checker;
- added the internal
  `deploy-scylla-vms.ansible-operation-initiation-report/v1` owner for only
  modeled read-only `check-jump-hosts`, accepting canonical cluster identity,
  one typed UUID, the bounded typed request, and the matching already-held
  operation-named cluster lock without caller journal payloads, paths, phases,
  events, plans, commands, variables, environments, or evidence;
- made initiation atomically create generation 1 of the unchanged common
  `deploy-scylla-vms.operation/v1` schema directly at
  `IN_PROGRESS/PLAN`, bound to exact operation/cluster identity and normalized
  non-secret request digest with null resume digest and no evidence until
  preparation resolves the plan;
- extended the existing journal transition owner so preparation may perform
  exactly one same-phase generation-2 append of the resolved PLAN checkpoint
  before binding creation, while preserving legacy preplanned journals and all
  downstream binding/execution/finalization compatibility;
- made exact untouched initiation idempotently reusable and refused changed
  requests/targets/kinds/clusters, UUID replay, another active operation,
  companion or advanced/terminal history, unsafe paths, and unmatched locks
  without overwrite, deletion, rollback, tool execution, or public workflow
  rewiring; atomic pre-publication failures leave no journal;
- added the independently versioned strict redacted
  `deploy-scylla-vms.ansible-check-jump-hosts-operation-report/v1` and one-call
  internal coordinator that composes the existing initiation owner with the
  existing resumable lifecycle under one caller-held operation-named lock;
- made missing and untouched generation-1 state call initiation before
  lifecycle, while generation-2, checkpoint, execution, semantic-evidence,
  finalization-only, VERIFY, and terminal prefixes validate the supplied typed
  request and enter lifecycle directly because initiation deliberately refuses
  advanced history;
- preserved exact component transition ownership, lock order, contention,
  typed application-error mapping, manual-recovery/no-retry behavior, terminal
  zero-write/zero-tool re-entry, strict report redaction, and the public
  `ClusterReadLock` checker's no-write behavior without adding CLI wiring or
  real Ansible execution in tests;
- extended local `show` checkpoint scanning and preparation duplicate detection
  to validate/recognize semantic-evidence and finalization companion filenames;
- added `routed-keyscan` as the thirty-second source-available catalog entry: a
  read-only, check-mode-safe, serial-one support playbook that reaches exactly
  one currently trusted jump through generated strict host-key-checking
  configuration and invokes only canonical `/usr/bin/ssh-keyscan` there with
  argv/no shell, fixed port/algorithms/locale, and bounded timeout/output;
- added strict independently versioned routed keyscan request, result, and
  in-memory candidate-collection contracts bound to current observation,
  inventory, trust, readiness, stable/provider identities, routes, collection
  time, source, and timeout policy, with stable-ID-only caller selection;
- kept endpoint-bearing module input `no_log`, validated all candidate wire
  keys/fingerprints and bounded statuses before returning address-free evidence,
  forced this source's Ansible log path to `/dev/null`, and blocked existing or
  changed trust without persistence, promotion, SSH-derivative writes,
  journaling, arbitrary scans, or public CLI wiring;
- added the immutable internal
  `deploy-scylla-vms.terraform-plan-checkpoint/v1` companion at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-plan.json`, created
  only under the matching already-held non-read-only operation lock from an
  existing canonical saved plan and bounded `terraform show -json` result;
- bound the checkpoint to exact request/initial-PLAN journal, desired metadata,
  generated tfvars, staged source, supported toolchain/plan format, canonical
  local-state serial and hashed lineage/snapshot, saved-plan bytes, and plan
  JSON, with immutable generation/digest guards and exact revalidation;
- added conservative address-free no-change/create-only/non-destructive/
  destructive action classification, separate none/review-required/conflict
  refresh-drift classification, bounded action counts, and hashed full/
  destructive/replacement/deletion/drift scopes without persisting plan/state
  values, resource addresses, lineage, or protected paths;
- added independently versioned
  `deploy-scylla-vms.terraform-plan-review/v1` output that keeps apply
  authorization `not-collected`, execution `unavailable`, and the apply command
  absent; fake-only tests cover malformed/unsupported plans, matching-lock and
  create-only persistence, secret/address/path omission, exact PLAN-evidence
  resume, and plan/state/JSON drift refusal without running Terraform;
- added the internal deploy-only `compose_deploy_plan_journal` API, accepting
  only canonical state-root/cluster identity, one operation UUID, and the
  matching already-held deploy lock while loading the immutable Terraform plan
  checkpoint from its canonical path;
- revalidated the exact initial common-journal preimage plus current metadata/
  desired, tfvars, staged source, canonical backend/state, supported toolchain,
  and saved-plan bindings before making the existing-v1 legal generation-1 to
  generation-2 `IN_PROGRESS/PLAN` transition;
- appended only one `PLAN/validated` event containing the checkpoint digest and
  `terraform-plan-reviewed` summary code, with checkpoint-first failure
  recovery, zero-write exact re-entry, and fail-closed conflicting/duplicate/
  advanced/terminal/execution/tampered/unsafe history handling;
- added independently versioned
  `deploy-scylla-vms.terraform-deploy-plan-composition-report/v1` output with
  created/reused state, journal/checkpoint/review schemas and digests, bounded
  action/drift counts and classes, replacement/deletion/drift booleans,
  address-free scope digests, authorization `not-collected`, execution intent
  `not-started`, apply execution `unavailable`, and destructive boundary
  `not-crossed`;
- preserved common journal v1 compatibility and kept plan values, resource
  addresses, provider identities, paths, commands, environments, credentials,
  secrets, authorization, state backup, apply execution, Terraform subprocesses,
  and public deploy wiring out of this slice;
- added the internal lock-bound `orchestrate_deploy_plan` API and independent
  `deploy-scylla-vms.terraform-deploy-plan-orchestration-report/v1`, accepting
  only canonical cluster identity, one deploy UUID, the matching held deploy
  lock, a controlled runner, and explicit validated Terraform executable/
  toolchain dependencies;
- made fresh PLAN generation load and revalidate the exact generation-1 journal,
  metadata/desired state, generated tfvars, staged source/work tree, canonical
  backend/state identity, unexpected-state policy, toolchain, and lock before
  effects, then run only fully anchored detailed plan and exact saved-plan show
  commands with the existing minimal environment;
- wrote Terraform output only to owner-only
  `<operation-uuid>.tfplan.staging`, required detailed exit 0/no-change or
  exit 2/change to agree with strict review evidence, validated complete
  prior-state/configuration/planned-value/resource-change/drift/output-change
  JSON in memory, atomically promoted unchanged bytes to
  `<operation-uuid>.tfplan`, persisted the immutable checkpoint, and invoked the
  existing journal composer in that order;
- added exact saved-plan-only and checkpoint-only recovery without automatic
  replanning, zero-tool/zero-write composed PLAN re-entry, immutable reviewed-
  plan retention, and fail-closed staging/temp/duplicate/path/link/permission/
  size/process/output/persistence and journal/state/source/tfvars/backend/
  toolchain conflict handling;
- retained no raw plan JSON/bytes, resource addresses, provider IDs, values,
  paths, commands, environment, diagnostics, credentials, or secrets in the
  orchestration report, and kept apply authorization uncollected, execution
  unavailable, apply/destroy construction absent from that planning slice, and
  CLI/public deploy wiring disabled; all Terraform plan/show tests use injected
  fake runners;
- added the internal lock-bound `authorize_deploy_apply` API plus independently
  versioned `deploy-scylla-vms.terraform-apply-authorization/v1`, normalized
  proof v1, and redacted report v1 contracts, accepting only canonical cluster
  identity, one deploy UUID, the matching held deploy lock, and a typed proof;
- made authorization canonically revalidate the exact generation-2 composed
  PLAN journal, immutable checkpoint/review/saved-plan, metadata/desired,
  tfvars/source, local backend/state, supported toolchain/format, and complete
  address-free class/count/scope bindings before any persistence;
- derived the effective class only from the reviewed plan: no-change plans
  create no authorization, create/update plans require ordinary interactive or
  `--yes` approval, and replacement/deletion plans require ordinary approval,
  separate normalized `--allow-destructive`, and exact destructive/
  replacement/deletion counts and scope digests;
- required separate interactive review for benign refresh drift, refused
  destructive refresh drift, limited absent initial state to drift-free
  create-only plans, and kept storage wipe, recreation, reprovision,
  decommission, and other narrow destructive proofs outside generic Terraform
  apply authorization;
- persisted only immutable owner-only
  `<operation-uuid>.terraform-apply-authorization.json`, with exact idempotent
  reuse and fail-closed proof/plan/journal/source/tfvars/backend/state/toolchain
  conflicts, while omitting resource addresses, plan values, prompts, entered
  text, operator/terminal/environment identity, commands, paths, keys,
  credentials, and secrets;
- kept the common v1 journal unchanged at `IN_PROGRESS/PLAN`, authorization
  unconsumed, execution not-started/unavailable,
  destructive boundary uncrossed, apply/destroy construction absent from that
  authorization slice, and public deploy wiring disabled;
- added internal lock-bound `safeguard_deploy_apply_state` plus independently
  versioned `deploy-scylla-vms.terraform-state-safeguard/v1` persistence and a
  strict redacted report v1, accepting only canonical cluster identity, one
  deploy UUID, and the matching already-held deploy lock;
- required the exact composed PLAN, saved-plan/checkpoint/review, current
  unconsumed authorization, desired/tfvars/source/backend/state/toolchain
  bindings, and apply-required classification before state safeguarding;
- added bounded owner-only descriptor-relative/no-follow local-state reads and
  atomic immutable exact-byte backups at
  `terraform/backups/<operation-uuid>.terraform.tfstate`, with minimal
  top-level identity parsing and replacement/mutation detection;
- added explicit verified-absent checkpoints for drift-free create-only initial
  plans without creating fake state or backup files, plus exact idempotent
  record/backup reuse and recoverable backup-only prefixes;
- made validation precede backup and backup precede the safeguard record;
  backup-write failure leaves no record, record-write failure can leave only
  the exact recoverable backup, and missing/orphaned/changed/unsafe artifacts
  fail closed without overwrite, deletion, rotation, pruning, restore, retry,
  authorization consumption, journal advancement, or apply construction;
- added the internal lock-bound `execute_deploy_apply` owner and independently
  versioned owner-only
  `deploy-scylla-vms.terraform-apply-execution/v1` transition record at
  `terraform/plans/<operation-uuid>.terraform-apply-execution.json`;
- added the sole exact-saved-plan apply builder using canonical executable,
  `-chdir`, cwd, plan path, local-backend environment, input refusal, backend
  locking, and fixed timeout/output bounds, with no auto-approve, destroy,
  target, replacement, refresh-only, parallelism, variable, workspace, proxy,
  config, or ambient Terraform argument;
- made apply execution revalidate journal, checkpoint/review/composition,
  immutable authorization and proof, safeguard and exact backup-or-absence,
  desired/tfvars/source/work tree/backend/pre-apply state, unexpected-state,
  toolchain, command, and classification bindings before durable intent and
  immediately before authorization consumption;
- ordered execution as retry-safe `prepared`, nonterminal common-journal
  `IN_PROGRESS/EXECUTE` intent evidence, durable `started` authorization
  consumption, exactly one controlled invocation, and bounded terminal process
  outcome; exact prepared prefixes can resume while started and later prefixes
  make no second runner call;
- recorded exit zero only as `process-succeeded-verification-pending`, while
  timeout, interruption, nonzero exit, output failure, malformed result, runner
  error, crash, and terminal-write ambiguity require manual recovery and forbid
  automatic retry, rollback, restore, deletion, replanning, or reapply;
- added strict redacted execution-report v1 plus fake-runner coverage for exact
  command/environment/cwd, present and absent pre-state, journal/write failure
  ordering, started-before-invocation, uncertain outcomes, replay, stale/
  missing/tampered artifacts, destructive proof conflicts, path/link/mode
  safety, and absence of raw output or protected values;
- added the internal lock-bound `verify_deploy_apply` continuation and
  independently versioned owner-only
  `deploy-scylla-vms.terraform-apply-verification/v1` companion at
  `terraform/plans/<operation-uuid>.terraform-apply-verification.json`;
- made post-apply verification require the exact
  `process-succeeded-verification-pending` execution, consumed authorization,
  unchanged plan/safeguard/desired/tfvars/source/backend/toolchain bindings,
  strict supported local-state identity, preserved existing lineage or valid
  initial lineage, advancing serial/digest, and descriptor/path stability
  before or around every effect;
- added the sole anchored post-apply `terraform output -json` invocation,
  strict complete host/image/network/storage parsing and current desired/input
  reconciliation, generation/digest-guarded `deploy-scylla-vms.observed/v1`
  persistence, nonterminal `IN_PROGRESS/VERIFY` journal progression with an
  exact prior-observation-or-absence baseline, exact observation-only recovery
  without an output rerun, and zero-process completed re-entry;
- added strict redacted verification-report v1 and fake-runner coverage for
  initial and existing state progression, exact output command/environment,
  malformed/sensitive/mismatched outputs, output failure, state path and
  concurrent-replacement safety, observation generation/recovery, immutable
  companion failure/reuse, and bound-input drift;
- added the internal lock-bound `generate_deploy_inventory` continuation and
  independently versioned immutable owner-only
  `deploy-scylla-vms.terraform-apply-inventory/v1` companion at
  `terraform/plans/<operation-uuid>.terraform-apply-inventory.json`;
- required the exact successful apply verifier, process-success execution and
  plan checkpoint, unchanged `IN_PROGRESS/VERIFY` journal, and current
  metadata/desired/tfvars/source/observation bindings before deterministic
  generation through the existing strict observation-to-inventory contract;
- wrote or reused only canonical owner-only `deploy-scylla-vms.inventory/v1`,
  with exact generation guards, byte-preserving reuse, same-model observation
  generation updates, companion-after-inventory ordering, and exact
  inventory-only recovery after companion persistence failure;
- classified existing SSH trust as missing/current/stale without rewriting it,
  required revalidation for semantically matching stale provenance, and
  refused inventory/trust membership, provider identity, topology, endpoint,
  route, unsafe-path, and orphan conflicts before overwrite;
- added strict redacted report and companion projections containing only
  schemas/generations/digests, bounded role/zone/host counts, address-free
  group/topology/route digests, trust/next-step state, and recovery flags;
  inventory content, addresses, provider IDs, routes, keys, fingerprints,
  protected paths, commands, environment, credentials, and secrets remain
  absent;
- added internal lock-bound `establish_deploy_ssh_trust` and immutable
  owner-only `deploy-scylla-vms.terraform-apply-trust/v1` at
  `terraform/plans/<operation-uuid>.terraform-apply-trust.json`;
- made trust consume only existing typed candidates and normalized per-key
  explicit-operator or independently matching SHA-256 fingerprint proofs,
  derive all identities/endpoints/routes from canonical inventory, and accept
  only Ed25519 and NIST P-256 ECDSA keys;
- added guarded jump-first staged trust, later routed-private trust only while
  exact jump provenance remains current, explicit complete stale-trust
  revalidation, conflict refusal for changed keys/identities/routes, and
  deterministic owner-only `trust.json`/`known_hosts`/`ssh_config` persistence;
- added trust/derivative-only recovery, complete-companion idempotence, strict
  redacted reports and companion bindings, plus fake-only coverage for proof,
  ordering, drift, malformed/extra/missing candidates, runtime/companion write
  failures, lock/path safety, redaction, and zero external process calls;
- added internal lock-bound `validate_deploy_ansible_readiness` and immutable
  owner-only `deploy-scylla-vms.terraform-apply-readiness/v1` at
  `terraform/plans/<operation-uuid>.terraform-apply-readiness.json`;
- required the exact complete apply-trust companion and current trust
  derivatives before any process call, rendered or reused only canonical
  owner-only `ansible.cfg`, probed the exact controlled sibling executables,
  and ran only controller-local `ansible-inventory --list`;
- added strict normalized static-inventory parity, in-memory fresh readiness,
  address-free companion/report bindings, explicit remote connectivity/health/
  playbook `not-performed` status, zero-process exact re-entry, and safe local
  repetition after companion-write failure;
- added fake-runner coverage for staged/missing/conflicting trust pre-run
  refusal, exact command/environment/config policy, toolchain failures,
  malformed/non-UTF-8/oversized output, host/group/hostvar/route conflicts,
  derivative drift, recovery, immutable conflict, lock enforcement, redaction,
  and absence of remote/playbook/Terraform/SSH calls;
- added internal lock-bound `bind_deploy_ansible_plan` with independent
  immutable owner-only `deploy-scylla-vms.ansible-deploy-context/v1` and
  `deploy-scylla-vms.ansible-deploy-plan/v1` records under
  `operations/<operation-uuid>.*`, avoiding the incompatible generic
  PLAN-phase Ansible checkpoint contract for this post-Terraform VERIFY stage;
- required the exact current verification/inventory/trust/readiness chain and
  current desired/source/observation/inventory/trust/config/catalog bindings,
  expanded the exact deploy mapping by stable role target with registry
  condition/limit/serial/check-mode policy, and bound target/variable/source/
  command and explicit blocker digests without accepting caller plan content
  or running a process;
- added a strict safe-intent allowlist plus truthful `not-performed`,
  `not-collected`, and `unmodeled` blockers for remote connectivity/evidence,
  storage/wipe/bootstrap/health/quorum/backup/capacity, Manager/backend, and
  monitoring prerequisites; added context-before-plan idempotence and partial-
  prefix recovery, strict redacted reports, local `show` validation, and
  fake-only drift/path/lock/redaction/no-process coverage;
- added internal lock-bound `execute_deploy_ansible_prerequisites` with
  generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-prerequisite-execution/v1` and immutable-
  prefix `deploy-scylla-vms.ansible-deploy-prerequisite-evidence/v1`
  companions under `operations/<operation-uuid>.*`;
- revalidated the exact verified Terraform-to-readiness chain, deploy
  context/plan, rendered controller/trust files, source/catalog, explicit
  executable/toolchain, and unchanged VERIFY journal before executing only
  controller-local inventory preflight then initial complete-host-set SSH
  connectivity with internally derived limits, fixed bounded timeouts, and no
  destination probes;
- added intent-before-effect, strict result-schema/command/target/complete-host
  validation, semantic-evidence-before-terminal ordering, manual-recovery/
  no-retry treatment for every uncertain or failed started attempt, exact
  succeeded-prefix resume, zero-process complete re-entry, address-free
  persistence/reporting, and fake-runner drift/failure/persistence/path/
  redaction coverage;
- added internal lock-bound `reconcile_deploy_ansible_plan` with immutable
  owner-only `deploy-scylla-vms.ansible-deploy-effective-plan/v1` at
  `operations/<operation-uuid>.ansible-deploy-effective-plan.json`, consuming
  only canonically loaded completed prerequisite execution/evidence and the
  unchanged full Terraform-to-readiness/context/original-plan/source/catalog
  chain;
- recomputed and required the exact original 21-position deploy mapping and
  every expanded condition/class/target/limit/serial/check-mode/variable/
  source/command identity, refusing incomplete, failed, uncertain, reordered,
  extra, stale, mismatched, or drifted evidence and mapping without silently
  replanning;
- marked only inventory preflight and initial complete-host connectivity
  `succeeded` with semantic-evidence bindings, retained later read-only facts as
  `not-performed`, and kept every mutating/sensitive/destructive step blocked
  with explicit class and authorization blockers;
- added atomic immutable persistence, exact zero-write reuse, original-artifact
  preservation, strict redacted status/count/blocker reporting, local-show
  companion validation, and fake-only drift/path/permission/write-failure/
  redaction/no-runner coverage without journal advancement;
- added internal lock-bound `execute_deploy_pre_mutation_host_evidence` as a
  distinct `pre-mutation-host-evidence` checkpoint that revalidates the full
  effective deploy/prerequisite/readiness/source/catalog/toolchain chain and
  invokes only the existing bounded read-only `evidence-collect` source over
  deterministic complete-host role batches;
- added owner-only
  `deploy-scylla-vms.ansible-deploy-pre-mutation-host-evidence-execution/v1`
  and immutable-prefix
  `deploy-scylla-vms.ansible-deploy-pre-mutation-host-evidence/v1`
  companions under `operations/<operation-uuid>.*`, with intent-before-call,
  semantic-evidence-before-success, exact succeeded-prefix recovery, zero-call
  completed re-entry, and permanent manual-recovery/no-retry treatment for
  every uncertain or failed started batch;
- retained only address-free bounded OS/architecture/capacity/mount, hashed
  device-set, allowlisted service, role-health, blocker, and provenance
  projections; added fake-runner coverage for exact batching, strict host/role
  membership, unsupported-platform blockers, malformed/non-UTF-8/oversized/
  failed/unreachable outcomes, drift, persistence/path/lock failures, and
  protected-field/raw-output/device-path/address redaction;
- kept the original effective plan and common `IN_PROGRESS/VERIFY` journal
  unchanged, with the mapped final `evidence-collect` step still
  `not-performed`; this checkpoint does not authorize or run any mutation,
  storage discovery, diagnostics persistence, finalization, or public workflow;
- added internal lock-bound `reconcile_deploy_pre_mutation_host_evidence` plus
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-host-evidence-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-host-evidence-reconciliation.json`,
  consuming only the canonically loaded full chain, prior effective plan, and
  exact completed pre-mutation execution/evidence;
- recomputed and preserved every original mapping/expanded-step identity while
  evaluating only bounded platform, reboot, service, capacity, mount, and
  role-applicable device gates; retained unknown/unsupported facts as explicit
  blockers without inferring package readiness, storage ownership, cluster
  emptiness, health, quorum, backup, or capacity safety;
- preserved inventory-preflight/connectivity success and final mapped
  `evidence-collect` as `not-performed`; permitted only next-ordered role-scoped
  `base-os` steps with passed applicable gates to become
  `evidence-ready-authorization-required`, never eligible or executable, while
  all later storage/package/configuration/bootstrap/health/Manager/monitoring
  steps remain blocked or not performed;
- added exact immutable reuse, fail-closed chain/mapping/evidence/path conflict
  handling, local-show companion validation, strict redacted gate/step/next-
  authorization/blocker reporting, and fake-only no-runner coverage without
  authorization persistence or journal advancement;
- kept mutation authorization out of that reconciliation owner and mutation
  execution, later evidence gates, finalization, destroy, direct service
  bypass, and CLI/public deploy wiring unavailable;
- added internal lock-bound `authorize_deploy_base_os` with immutable owner-only
  `deploy-scylla-vms.ansible-deploy-base-os-authorization/v1` at
  `operations/<operation-uuid>.ansible-deploy-base-os-authorization.json`,
  deriving its complete mutating scope only from exact
  `evidence-ready-authorization-required` reconciliation statuses;
- restricted authorization to active mapping-position-three `base-os`
  instances and ordinary interactive or PLAN-permitted `--yes` approval,
  rejecting absent/denied/malformed proof, destructive flags/scope proof,
  missing/extra/wrong/later-stage targets, uncertain execution, and every
  context/plan/evidence/readiness/source/catalog/journal drift before write;
- bound exact journal, context/plans/reconciliations/evidence/readiness/source/
  catalog and step sequence/playbook/source/command/target/variable digests
  plus stable-ID set/count and normalized proof digest, with exact zero-write
  reuse, owner-only atomic persistence, strict redacted reporting, local-show
  validation, and fake-only lock/path/failure/redaction/no-runner coverage; and
- kept authorization unconsumed, all step statuses and the common
  `IN_PROGRESS/VERIFY` journal unchanged, execution and finalization
  unavailable, and every later deploy stage and CLI/public workflow pending;
- added internal lock-bound `execute_deploy_base_os` with generation-guarded
  owner-only `deploy-scylla-vms.ansible-deploy-base-os-execution/v1` and
  immutable-prefix `deploy-scylla-vms.ansible-deploy-base-os-evidence/v1`
  companions under `operations/<operation-uuid>.*`;
- made execution derive every authorized mapping-position-three scope,
  stable-ID limit, typed Ubuntu 24.04/image-architecture variables,
  guest-architecture parity, and anchored command from the immutable
  authorization and canonical current chain, with no caller-provided step/
  playbook/target/limit/variable/command/environment/result surface;
- added durable prepared-before-start intent, started-record authorization
  consumption immediately before each exact controlled call, strict result
  schema and complete unique host membership validation, semantic-evidence-
  before-terminal ordering, and address-free platform/change/reboot/timesync
  projections;
- made every uncertain started attempt, timeout, interruption, nonzero,
  unreachable, non-UTF-8, oversized or malformed result, drift, and
  post-invocation persistence failure permanently manual-recovery/no-retry,
  while permitting exact pre-start prepared recovery and zero-process completed
  re-entry;
- added fake-runner coverage for exact command/scope/typed variables,
  started-before-call ordering, changed/no-change/reboot evidence, strict
  malformed/membership/failure/timeout/interruption/output handling,
  persistence-prefix recovery, no replay, drift, lock/path/permission safety,
  redaction, and absence of unrelated playbook/Terraform/SSH calls; and
- kept the effective plan and common `IN_PROGRESS/VERIFY` journal unchanged,
  with no reboot, package rollback, image restore, another playbook,
  finalization, or CLI/public deploy wiring at the execution boundary;
- added internal lock-bound `reconcile_deploy_base_os_result` with immutable
  owner-only `deploy-scylla-vms.ansible-deploy-base-os-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-base-os-reconciliation.json`,
  canonically revalidating the full deploy chain and exact terminal-success
  authorization/execution/evidence scope before any write;
- preserved every recomputed mapping/expanded-step identity, promoted only exact
  completed `base-os` instances to evidence-bound `succeeded`, retained changed
  versus already-current as bounded evidence, and refused incomplete, uncertain,
  wrong-host, stale, drifted, or conflicting prefixes;
- added explicit `reboot-required` and `reboot-handling-not-performed` blockers
  that leave every later active step blocked without reboot or reconnect; when
  no reboot is required, only the exact next independently proven gate may
  become authorization-required or read-only eligible, with no leapfrogging and
  final mapped evidence still `not-performed`;
- added atomic owner-only no-follow persistence, exact zero-write reuse, local
  show validation, strict redacted status/count/digest reporting, and fake-only
  drift/path/permission/write-failure/no-runner coverage while keeping
  authorization/execution intent, journal transition, reboot, later stages,
  finalization, and CLI/public deploy wiring pending;
- added internal lock-bound `plan_and_authorize_deploy_reboots` with immutable
  owner-only `deploy-scylla-vms.ansible-deploy-reboot-plan/v1` and
  `deploy-scylla-vms.ansible-deploy-reboot-authorization/v1` companions at
  `operations/<operation-uuid>.ansible-deploy-reboot-plan.json` and
  `operations/<operation-uuid>.ansible-deploy-reboot-authorization.json`;
- derived reboot scope only from exact successful base-OS semantic evidence
  marked `reboot-required`, preserved exact base-OS execution order with
  stable-ID tie-breaking and serial one, bound current inventory/trust/routes/
  connectivity, and blocked incomplete or unsafe jump-dependent ordering;
- required future per-target reconnect, identity/trust revalidation, machine
  evidence, and reboot-clear checkpoints before any next target, while
  accepting only ordinary interactive or PLAN-permitted `--yes` approval and
  rejecting destructive proof for this mutating deploy stage;
- added strict no-reboot `not-required` behavior, plan-before-authorization
  persistence, plan-only recovery, exact zero-write reuse, local-show
  validation, and fake-only proof/drift/path/permission/write-failure/redaction/
  no-process coverage; and
- kept reboot authorization unconsumed, execution unavailable, reconnect
  `not-performed`, all reconciled step statuses and the common
  `IN_PROGRESS/VERIFY` journal unchanged, with no reboot, execution record,
  later deploy stage, finalization, CLI, or public workflow enabled;
- added the thirty-third hash-checked catalog source, deployment-only
  `deploy-reboot`, as Ubuntu-24.04-only, exact-one-target, serial-one/fatal,
  check-mode-refused support using fixed inactive-service gates, an in-memory
  hashed boot identity, and bounded `ansible.builtin.reboot`;
- added internal lock-bound `execute_deploy_reboots` with owner-only
  `deploy-scylla-vms.ansible-deploy-reboot-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-reboot-evidence/v1` companions under
  `operations/<operation-uuid>.*`, binding the complete deploy/reboot/
  connectivity/trust/readiness/source/catalog/toolchain chain and exact ordered
  per-target plan/variable/command/request/result/evidence digests;
- made the first durable `started` intent consume authorization for the exact
  ordered reboot scope, required complete strict semantic reconnect,
  boot-change, stable identity, trust, machine, service-safety, and reboot-clear
  evidence before terminal success or the next target, and preserved exact
  complete zero-process re-entry;
- made every started crash, timeout, interruption, unreachable/nonzero call,
  malformed/non-UTF-8/oversized result, identity/trust/platform/reconnect/
  reboot-clear mismatch, drift, or post-call persistence failure permanently
  manual-recovery/no-retry without skip, continuation, rollback, trust rewrite,
  Terraform, unrelated playbook, or automatic second reboot;
- added fake-runner execution coverage for durable intent/authorization
  consumption, strict success and reuse, no-reboot no-write/no-process behavior,
  semantic-gate failures, timeout/interruption/failure/unreachable/output
  refusal, no retry or continuation, narrow API/lock enforcement, persisted
  schema/redaction checks, and sole-playbook invocation; and
- kept the common journal and deploy-step reconciliations unchanged at
  `IN_PROGRESS/VERIFY` at the reboot execution boundary;
- added internal lock-bound `reconcile_deploy_post_reboot_plan` with immutable
  owner-only
  `deploy-scylla-vms.ansible-deploy-post-reboot-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-post-reboot-reconciliation.json`,
  loading and revalidating the complete canonical deploy/reboot chain without
  accepting caller statuses, targets, order, results, steps, variables,
  commands, paths, runners, or toolchains;
- recorded no-reboot handling as `not-required` only with absent reboot
  artifacts, and required exact complete ordered terminal-success execution,
  consumed authorization, and true reconnect/boot-change/identity/trust/
  machine/service-safety/reboot-clear semantic evidence for every reboot target;
- recomputed the complete deploy mapping without rewriting prior records,
  retained evidence-bound base-OS success, cleared only exact reboot blockers,
  advanced only the immediate proven jump-host configuration scope to
  `evidence-ready-authorization-required`, and kept every later scope blocked or
  not performed;
- added atomic owner-only no-follow persistence, exact zero-write reuse,
  local-show validation, strict redacted branch/count/set/order/blocker/digest
  reporting, and fake-only coverage for both branches, complete and invalid
  evidence, uncertainty, drift, path/permission/write safety, no leapfrog, and
  zero process calls; and
- kept next-step authorization/execution, later deploy stages, journal
  transition, finalization, CLI, and public workflow pending;
- added internal lock-bound `authorize_deploy_jump_host_configure` with
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-authorization/v1` at
  `operations/<operation-uuid>.ansible-deploy-jump-host-configure-authorization.json`,
  deriving its complete mutating scope only from exact post-reboot
  `evidence-ready-authorization-required` mapping-position-four
  `jump-host-configure` instances and canonical jump-host inventory identities;
- accepted only ordinary interactive or PLAN-permitted `--yes` approval,
  rejected missing/denied/malformed and destructive proof, caller scope and
  uncertain execution history, and revalidated the complete context/plan/
  prerequisite/host/base-OS/reboot/inventory/trust/readiness/source/catalog/
  journal chain before persistence;
- bound exact post-reboot reconciliation, step sequence/source/command/target/
  variable/evidence digests, stable-ID count/set, mutating classification, and
  normalized proof method/digest with owner-only atomic persistence, immutable
  conflict refusal, exact zero-write reuse, strict redacted reporting,
  local-show validation, and fake-only drift/path/permission/write-failure/
  redaction/no-process coverage; and
- kept the authorization-stage artifact unconsumed, every step and the common
  `IN_PROGRESS/VERIFY` journal unchanged, and all execution ownership, later
  deploy stages, finalization, CLI, and public workflow outside that
  authorization-only layer;
- added internal lock-bound `execute_deploy_jump_host_configure` with
  generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-evidence/v1`
  companions under `operations/<operation-uuid>.*`;
- made execution derive each ordered mapping-position-four scope, exact-one
  jump stable-ID limit, role-level configuration authorization, PermitOpen
  routes, rendered policy, typed variables, playbook source, and anchored
  command from the immutable authorization and current canonical chain, with no
  caller step/playbook/target/limit/variable/path/command/environment/result
  surface;
- added retry-safe prepared intent, durable started-before-call authorization
  consumption without authorization rewrite, strict result and target
  validation, semantic-evidence-before-terminal ordering, and address-free
  policy/route/config/configuration-authorization/result/source digest
  bindings with changed/applied/validation/reload/restoration truth;
- made every uncertain started attempt, timeout, interruption, nonzero,
  unreachable, malformed/non-UTF-8/oversized output, identity/trust/policy/
  route/config mismatch, sshd validation/reload failure, post-call drift, and
  persistence failure permanently manual-recovery/no-retry, without treating
  the role's bounded internal restore behavior as proof of safe retry;
- added fake-runner coverage for exact command/scope/order/typed payload,
  started-before-call persistence, changed/no-change success, validation/
  reload/restore outcomes, malformed membership/output/process failures,
  prepared recovery, no replay, full-chain/toolchain/config drift, lock/path/
  permission safety, redaction, and sole-playbook execution; and
- kept the immutable authorization, post-reboot reconciliation, deploy-step
  statuses, and common `IN_PROGRESS/VERIFY` journal unchanged, with no
  connectivity rerun, later playbook, next-plan reconciliation, finalization,
  CLI, or public workflow enabled;
- added internal lock-bound `reconcile_deploy_jump_host_configure_result` with
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-jump-host-configure-reconciliation/v1`
  at
  `operations/<operation-uuid>.ansible-deploy-post-jump-host-configure-reconciliation.json`,
  accepting only canonical operation identity and the matching held deploy
  lock;
- revalidated the complete deploy chain through current jump-host
  authorization/execution/evidence, reconstructed exact policy, PermitOpen
  routes, rendered configuration, source, variables, and command intent, and
  required complete unique terminal-success semantic evidence with successful
  validation, exact changed/reload parity, and restore-not-required truth;
- made prepared/started/failed/uncertain/manual-recovery, missing/extra/
  duplicate/wrong-target, validation/reload/restore ambiguity, policy/route/
  configuration mismatch, and full-chain provenance drift fail before
  persistence;
- recomputed the complete mapping, marked only exact jump-host configuration
  scopes evidence-bound `succeeded`, derived rather than hard-coded the first
  remaining active mapping, advanced only its fully proven scopes to read-only
  `eligible` or mutating `evidence-ready-authorization-required`, and kept all
  later storage/package/configuration/bootstrap/health/Manager/monitoring/
  final-evidence/public stages blocked or not performed;
- added atomic owner-only no-follow persistence, exact zero-write reuse,
  local-show validation, strict redacted count/status/next-step/blocker/digest
  reporting, and fake-only changed/no-change, evidence ambiguity, uncertainty,
  drift, no-leapfrog, path/permission/write-failure, redaction, and zero-runner
  coverage; and
- kept next-gate authorization/execution, trust mutation, journal transition,
  finalization, CLI, and public deploy wiring pending;
- added internal lock-bound `execute_deploy_final_routes_connectivity` with
  owner-only
  `deploy-scylla-vms.ansible-deploy-final-routes-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-final-routes-evidence/v1` companions under
  `operations/<operation-uuid>.*`;
- made the executor reload the complete post-jump-host deploy chain and derive
  the sole eligible final-routes `connectivity-check`, exact jump stable-ID
  limits, and documented destination role/port probes from immutable mapping
  and RFC 1918 inventory-assigned routes, with no caller playbook, target,
  probe, variable, command, path, environment, result, or status surface;
- added anchored controlled Ansible execution, durable started-before-call
  intent, strict source/step/command/result and exact host/pair membership
  checks, address-free semantic evidence, and permanent manual-recovery/no-
  retry handling for every started uncertainty, failed/unreachable/nonzero or
  malformed result, drift, and post-call persistence failure;
- added internal lock-bound `reconcile_deploy_final_routes_connectivity` with
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-final-routes-reconciliation/v1`,
  marking only final-routes connectivity evidence-bound succeeded and deriving
  only the immediate next mapping gate without leapfrogging;
- added fake-runner coverage for exact route/limit/command derivation, strict
  success and zero-call re-entry, missing/extra/duplicate/wrong host or pair,
  timeout/interruption/nonzero/unreachable/malformed/non-UTF-8/oversized
  outcomes, durable intent/no retry, full-chain and toolchain drift, public/
  direct/arbitrary probe refusal, safe persistence prefixes, immutable
  reconciliation, paths/permissions/redaction, and sole-playbook execution;
- kept the common journal at `IN_PROGRESS/VERIFY`, with next non-jump `base-os`
  execution/reconciliation, later stages, finalization, CLI, and public deploy
  wiring pending;
- added internal lock-bound `authorize_deploy_non_jump_base_os` with distinct
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-authorization/v1` at
  `operations/<operation-uuid>.ansible-deploy-non-jump-base-os-authorization.json`,
  separate from the earlier completed jump-scope base-OS authorization;
- made the authorization owner reload and recompute the complete canonical
  chain through final-routes reconciliation, current pre-mutation host
  evidence, inventory, trust, readiness, source, catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal before deriving only the exact active mutating
  mapping-position-six non-jump `base-os` scope;
- refused jump, overlapping earlier, extra, missing, wrong, inactive,
  non-ready, broadened, drifted, or ambiguous targets and uncertain execution
  history, with no caller-owned step, target, role, limit, variable, command,
  path, classification, scope, prompt, or free-form text surface;
- accepted only ordinary interactive or PLAN-permitted `cli-yes` proof,
  rejected denied/malformed/destructive/narrow proof, and bound stage/scope,
  exact step/source/command/variable/target, final-routes and host-evidence,
  and full provenance digests;
- added atomic owner-only no-follow immutable persistence, exact zero-write
  reuse, redacted schema/stage/scope/approval/count/set/blocker/journal
  reporting, and fake-only scope, drift, uncertainty, path, permission,
  conflict, write-failure, redaction, idempotence, and zero-runner coverage;
- added internal lock-bound `execute_deploy_non_jump_base_os` with distinct
  generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-evidence/v1` companions at
  `operations/<operation-uuid>.ansible-deploy-non-jump-base-os-{execution,evidence}.json`;
- made the execution owner reload and recompute the complete canonical chain
  through final-routes reconciliation and the distinct non-jump authorization,
  then derive only exact mapping-position-six non-jump stable IDs, source,
  typed Ubuntu/architecture variables, and anchored `base-os` command;
- refused jump or earlier-scope overlap, missing/extra/non-ready targets,
  OS/architecture/reboot/service/capacity/route blockers, stale or consumed
  authorization, uncertain execution, toolchain, source/catalog, trust,
  readiness, evidence, reconciliation, and journal drift before invocation;
- added retry-safe prepared intent, durable started-before-call whole-scope
  authorization consumption, strict complete semantic result projection,
  permanent manual-recovery/no-retry handling after every started uncertainty,
  succeeded-prefix recovery, and zero-process complete re-entry;
- added fake-controlled-runner coverage for exact multi-host scope/order/
  command/variables, jump exclusion, changed/no-change/reboot results,
  malformed/wrong/missing/extra/duplicate evidence, process and persistence
  failures, no retry/replay, prepared recovery, full-chain drift, canonical
  paths/permissions, redaction, and sole-playbook execution;
- kept the immutable authorization, earlier artifacts, effective plan, and
  common journal unchanged, with reboot handling, all later stages,
  finalization, CLI, and public wiring pending;
- added internal lock-bound `reconcile_deploy_non_jump_base_os_result` with
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-non-jump-base-os-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-post-non-jump-base-os-reconciliation.json`;
- made reconciliation reload the complete canonical chain through exact
  terminal non-jump authorization/execution/evidence, require complete unique
  success for the authorized non-jump scope, and refuse every prepared,
  started, failed, uncertain, manual-recovery, malformed, missing, extra,
  duplicate, wrong-scope, stale, or provenance-drifted prefix;
- recomputed the full mapping, marked only mapping-position-six non-jump
  `base-os` distinctly evidence-bound succeeded, retained changed/current/
  reboot counts, blocked all later active work on reboot without reusing the
  earlier jump reboot chain, and otherwise derived only immediate Scylla
  `storage-discover` as eligible with no leapfrog;
- added atomic owner-only no-follow exact reuse, redacted bounded report
  projection, and fake-only no-change/changed/mixed/all-reboot, ambiguity,
  uncertainty, drift, next-gate, old-reboot-separation, path/permission,
  write-failure, redaction, idempotence, and zero-call coverage; and
- kept non-jump reboot planning/handling, storage-discovery execution, later
  stages, finalization, journal transition, CLI, and public wiring pending;
- added internal lock-bound `plan_and_authorize_deploy_non_jump_reboots` with
  distinct immutable owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-plan/v1` and
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-authorization/v1` records
  at
  `operations/<operation-uuid>.ansible-deploy-non-jump-reboot-{plan,authorization}.json`;
- made planning reload and recompute the complete chain through exact
  post-non-jump-base-OS reconciliation and derive only successful non-jump
  stable IDs whose strict base-OS result requires reboot, without reusing or
  overwriting earlier jump-scope reboot artifacts;
- added deterministic serial-one base-execution order, canonical jump-route
  and final-routes checks, exact inventory/trust/readiness/source/catalog/
  journal binding, stable connectivity/route/order blockers, and mandatory
  future reconnect, identity/trust, machine-evidence, service-safety, and
  reboot-clear gates;
- accepted only ordinary interactive or PLAN-permitted `cli-yes` approval,
  rejected destructive or changed proof, bound authorization to exact scope/
  order/route/provenance digests, and kept it unconsumed with execution
  unavailable and the journal unchanged;
- added plan-first exact recovery, atomic owner-only no-follow persistence,
  immutable zero-write reuse, strict no-reboot/no-artifact behavior preserving
  the `storage-discover` branch, and redacted schema/count/state/blocker/digest
  reports;
- added fake-only no-reboot, one/all-target, exact order/route, scope/proof/
  drift, earlier-artifact separation, blocked-plan, partial recovery,
  persistence-failure, lock/path/permission, redaction, idempotence, and
  zero-process coverage; and
- added internal lock-bound `execute_deploy_non_jump_reboots` with distinct
  generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-evidence/v1` companions at
  `operations/<operation-uuid>.ansible-deploy-non-jump-reboot-{execution,evidence}.json`;
- made execution reload and recompute the full chain through exact non-jump
  plan/authorization and post-non-jump-base-OS reconciliation, derive only the
  immutable serial-one target order and typed hash-checked `deploy-reboot`
  calls, and keep the earlier jump-scope artifact family separate and
  unchanged;
- persisted `prepared` and then `started` before every target, consumed the
  distinct whole-scope authorization on first started intent, allowed only
  strict succeeded-prefix continuation, and made complete re-entry zero-call;
- required exact address-free target/role/Ubuntu/architecture, reconnect,
  changed boot identity, current trust, machine evidence, pre/post service
  safety, and reboot-clear semantics rather than trusting exit zero;
- made every started crash, timeout, interruption, failure, unreachable or
  malformed result, semantic mismatch, drift, and persistence failure
  manual-recovery/no-retry with no skip, continuation, rollback, or trust
  rewrite;
- added fake-only exact order/scope, prepared-prefix resume, strict semantic and
  process failure gates, no-retry, full-chain drift, artifact separation,
  persistence/path/permission, redaction, local companion recognition,
  sole-playbook, and zero-call re-entry coverage; and
- added internal lock-bound `reconcile_deploy_post_non_jump_reboot_plan` with
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-non-jump-reboot-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-post-non-jump-reboot-reconciliation.json`;
- made the no-reboot branch require absent distinct reboot artifacts and made
  the reboot-required branch require exact ordered terminal success, consumed
  execution authorization, no uncertainty, and complete reconnect/boot/
  identity/trust/machine/service/reboot-clear semantic gates;
- refused partial, prepared, started, failed, unreachable, malformed, missing,
  extra, reordered, stale, drifted, or mismatched state before persistence,
  while preserving every prior record and the unchanged VERIFY journal;
- cleared reboot blockers only after complete proof, derived only the first
  remaining active mapping, advanced current read-only Scylla
  `storage-discover` to eligible, and prevented every later gate from
  leapfrogging;
- added atomic owner-only no-follow immutable persistence, exact zero-write
  reuse, local `show` companion recognition, redacted bounded reports, and
  fake-only both-branch, semantic-gate, uncertainty, drift, path, permission,
  idempotence, next-gate, redaction, and zero-call coverage;
- kept storage-discovery execution, later stages, finalization, journal
  transition, CLI, and public wiring pending;
- added internal lock-bound `execute_deploy_storage_discovery`, deriving the
  exact eligible sorted Scylla scope and invoking only hash-checked catalog
  `storage-discover` through the controlled Ansible service;
- added owner-only
  `deploy-scylla-vms.ansible-deploy-storage-discovery-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-storage-discovery-evidence/v2` records at
  `operations/<operation-uuid>.ansible-deploy-storage-discovery-execution.json`
  and
  `operations/<operation-uuid>.ansible-deploy-storage-discovery-evidence.json`;
- required durable started intent, exact strict schema/provenance and complete
  unique host/device membership, and retained only address-free bounded
  statuses/counts plus hashed device/signature/ownership/topology evidence;
- made every started process, malformed/nonzero/unreachable result, semantic,
  drift, and persistence uncertainty manual-recovery/no-retry, with exact
  complete re-entry making zero process calls;
- added internal subprocess-free `reconcile_deploy_storage_discovery` with
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-storage-discovery-reconciliation/v1`
  at
  `operations/<operation-uuid>.ansible-deploy-post-storage-discovery-reconciliation.json`;
- marked only exact storage discovery succeeded, advanced only immediate
  read-only Scylla `storage-preflight` when its gates are proven, and kept
  storage mutation authorization, leapfrog, journal transition, finalization,
  CLI, and public wiring absent;
- added fake-only scope/command, strict host/device/result, uncertainty/
  no-retry, drift, path/permission, redaction, immutable reconciliation,
  local-show recognition, and no-leapfrog/no-mutation coverage;
- advanced deploy storage-discovery semantic evidence to
  `deploy-scylla-vms.ansible-deploy-storage-discovery-evidence/v2`, retaining
  only the exact address-free, device-path-free storage-preflight projection
  needed by the next internal read-only owner;
- added lock-bound internal `execute_deploy_storage_preflight`, deriving exact
  sorted Scylla scope and typed desired/manifest/discovery variables and
  invoking only hash-checked catalog `storage-preflight` in check mode;
- added owner-only
  `deploy-scylla-vms.ansible-deploy-storage-preflight-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-storage-preflight-evidence/v1` companions,
  with durable started intent, strict exact schema/host/result validation,
  address-free and device-path-free disposition/action/capacity/blocker/status
  evidence, and permanent manual-recovery/no-retry after uncertainty;
- added immutable
  `deploy-scylla-vms.ansible-deploy-post-storage-preflight-reconciliation/v1`,
  marking only exact storage preflight succeeded, retaining blocked hosts,
  excluding `owned-noop` from authorization, deriving immediate preparation
  scope only for `prepare-required`, and keeping wipe-required host/device-set
  scope separate for later explicit consent;
- kept storage mutation and preparation authorization collection/execution
  absent from the preflight-reconciliation owner, along with later-gate
  leapfrog, journal transition, finalization, CLI, and public wiring, with
  local `show` recognition and fake-only action, mixed-scope, mismatch,
  uncertainty/no-retry, permission, redaction, and re-entry coverage;
- added internal lock-bound `authorize_deploy_storage_prepare`, deriving only
  exact `prepare-required` destructive host scopes from the immutable
  post-storage-preflight reconciliation while excluding `owned-noop` and
  blocked results;
- added distinct
  `deploy-scylla-vms.ansible-deploy-storage-prepare-general-proof/v1` and
  `deploy-scylla-vms.ansible-deploy-storage-prepare-wipe-proof/v1` decisions:
  ordinary approval, `--allow-destructive`, and exact preparation scope are
  always required, while separate exact wipe consent is required only for the
  wipe-required subset and `--yes` alone is insufficient;
- persisted immutable owner-only
  `deploy-scylla-vms.ansible-deploy-storage-prepare-authorization/v1` at
  `operations/<operation-uuid>.ansible-deploy-storage-prepare-authorization.json`,
  binding the complete plan/evidence/inventory/trust/readiness/source/catalog/
  journal chain and per-host action/disposition/device-set/intent digests;
- added redacted
  `deploy-scylla-vms.ansible-deploy-storage-prepare-authorization-report/v1`,
  local `show` recognition, exact zero-write reuse, fail-closed proof/drift/
  path/persistence behavior, and fake-only policy coverage;
- added internal lock-bound `execute_deploy_storage_prepare`, deriving only
  exact ordered `prepare-required` scopes and invoking hash-checked catalog
  `storage-prepare` one target at a time with controlled variables and check
  mode refused;
- persisted owner-only
  `deploy-scylla-vms.ansible-deploy-storage-prepare-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-storage-prepare-evidence/v1` companions,
  with durable prepared/started intent, first-start general-authorization
  consumption, and wipe-proof consumption only at exact wipe-required target
  boundaries;
- strengthened strict storage-prepare results with immediate public
  device-identity revalidation plus exact action/disposition/device-set/
  provenance, wipe application, mutation-boundary, first-irreversible-step,
  completed-state, and post-action-verification evidence; exit zero alone is
  insufficient;
- made every uncertain started storage-preparation outcome permanent
  manual-recovery/no-retry/no-skip/no-continue/no-rollback, added zero-process
  completed re-entry and local `show` recognition, and kept evidence free of
  addresses, provider IDs, device paths/serials, commands, variables, raw
  output, credentials, and secrets;
- added immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-storage-prepare-reconciliation/v1` at
  `operations/<operation-uuid>.ansible-deploy-post-storage-prepare-reconciliation.json`,
  with full-chain revalidation, exact complete terminal-success/proof
  consumption checks, and fail-closed partial/uncertain/mismatch/drift behavior;
- marked only exact `prepare-required` scopes evidence-bound succeeded,
  preserved current `owned-noop` scopes as explicitly not mutated, retained
  blocked storage, and derived only the immediate exact read-only
  `storage-postcheck` scope without package-install or later-gate leapfrog;
- added redacted
  `deploy-scylla-vms.ansible-deploy-post-storage-prepare-reconciliation-report/v1`,
  immutable zero-write reuse, local `show` recognition, and mixed action,
  wipe/non-wipe, uncertainty, proof, drift, path, permission, persistence, and
  redaction coverage;
- kept journal transition, finalization, CLI, and public storage-preparation
  wiring unavailable;
- added the internal operation-bound
  `execute_deploy_storage_postcheck` owner with full-chain validation through
  post-storage-prepare reconciliation, exact serial-one/check-mode command
  derivation, durable started intent, strict all-check semantic results, and
  permanent manual-recovery/no-retry behavior after any uncertain or failed
  invocation;
- added owner-only
  `deploy-scylla-vms.ansible-deploy-storage-postcheck-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-storage-postcheck-evidence/v1` records with
  path-free hashed device identities, bounded capacity/status counts, and
  provenance/blocker digests, including exact prepared and `owned-noop`
  semantics;
- added immutable
  `deploy-scylla-vms.ansible-deploy-post-storage-postcheck-reconciliation/v1`,
  which accepts only complete current postcheck success, marks only the exact
  postcheck scopes succeeded, and advances only immediate `scylla-install`
  scopes to authorization-required without health inference or later-gate
  leapfrog;
- added local `show` recognition and kept the common
  `IN_PROGRESS/VERIFY` journal unchanged, exact completed re-entry
  zero-process/zero-write;
- added internal `scylla-install` authorization with v1 proof, immutable
  authorization, and redacted report schemas; full-chain validation through
  post-storage-postcheck reconciliation; exact Scylla stable-ID and
  catalog-bound 2026.2 package/repository/signing-key provenance; ordinary
  interactive or `cli-yes` approval only; destructive-proof refusal; and
  owner-only local `show` recognition;
- added internal lock-bound `execute_deploy_scylla_install` with full-chain,
  authorization, base-OS, source/catalog, readiness, and controlled-toolchain
  revalidation; exact authorized serial-one scope and command derivation; and
  durable prepared/started intent that consumes authorization only at the first
  started boundary;
- persisted owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-install-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-scylla-install-evidence/v1` companions,
  accepting only exact successful 2026.2 package/repository/signing-key
  evidence with `scylla-server` masked and inactive and all configuration,
  storage, tuning, Manager, and service-start actions absent;
- made every uncertain started install outcome permanent
  manual-recovery/no-retry/no-skip/no-continue/no-rollback, added exact
  zero-process completed re-entry and local `show` recognition, and kept
  persisted reports free of addresses, provider IDs, commands, variables,
  protected paths, raw output, credentials, and secrets;
- added immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-scylla-install-reconciliation/v1`
  with complete-chain revalidation, exact terminal package/provenance and
  masked/inactive-service evidence, prohibited-action refusal, exact
  install-step success binding, immediate `scylla-configure`
  authorization-required derivation, later-gate refusal, count/digest-only
  reporting, zero-write re-entry, and local `show` recognition;
- added internal immutable operation-bound `scylla-configure` authorization
  with distinct v1 proof, authorization, and redacted report schemas; full
  chain validation through post-install reconciliation; exact canonical
  target and cluster/datacenter/rack/private-identity, stable-ID seed, 2026.2,
  fixed-directory, template/source/variable/command/rendered-intent derivation;
  masked/inactive service policy; ordinary interactive or `cli-yes` approval
  only; destructive-proof refusal; exact zero-write reuse; owner-only local
  `show` recognition; and no process execution or authorization consumption;
- added internal operation-bound `scylla-configure` execution with distinct
  owner-only immutable-prefix v1 execution/evidence and redacted report
  schemas; full-chain and exact authorization revalidation; exact authorized
  serial-one target/configuration derivation; durable prepared/started intent
  with first-start authorization consumption; strict 2026.2, exact two-file,
  root-`0644`, topology/seed/data/template/config-digest,
  masked/inactive-service, runtime-validation-false, and prohibited-action
  evidence; exit-zero-insufficient parsing; permanent no-retry recovery after
  started uncertainty; prepared-prefix resume; completed zero-process re-entry;
  and local `show` recognition;
- added immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-scylla-configure-reconciliation/v1`
  with complete-chain revalidation, exact terminal two-file/topology/seed/
  version/data-directory/ownership/mode/service/prohibited-action evidence,
  exact configure-step success binding, count/digest-only reporting,
  zero-write reuse, and local `show` recognition;
- preserved the original immutable 21-position deploy mapping, which
  historically omits `scylla-bootstrap`, and added truthful
  `bootstrap-plan-required` / `bootstrap-step-unmodeled` refusal with
  bootstrap/empty-cluster/topology/seed/health/capacity evidence
  `not-performed` and no next mutation authorization or execution until a
  separately versioned bootstrap context/plan is implemented;
- added separate immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-context/v1` and
  `deploy-scylla-vms.ansible-deploy-scylla-bootstrap-plan/v1` companions with
  full-chain revalidation through post-configuration, exact initial Terraform
  absent-state or create-only/drift-free initial-observation apply binding,
  normalized reviewed new-cluster/empty-cluster/capacity proof, prior
  membership-artifact refusal, masked/inactive and never-started service proof,
  and local `show` validation;
- derived the initial-seed and serial-one join order only from canonical stable
  identities, configured seed and topology policy; bound unknown-before-start
  Host-ID state plus package/storage/config/source/topology/seed/capacity
  digests; kept joins waiting for preceding bootstrap and complete
  survivor/absence/capacity/schema health checkpoints; and persisted only
  redacted counts, enums, and digests;
- added context-before-plan partial recovery, exact zero-write reuse, changed
  proof/provenance refusal, and tests for complete/incomplete empty proof,
  prior-state/service/artifact blockers, deterministic ordering, initial versus
  join status, health/capacity gates, path safety, drift, redaction, and zero
  process calls;
- added distinct immutable owner-only initial-seed bootstrap authorization
  proof/record/report v1 schemas and local `show` validation, with full-chain
  and exact context/plan reproduction, sensitive classification, ordinary
  interactive or `cli-yes` approval, separate exact digest-only initial-seed
  scope acknowledgement, destructive-proof refusal, and zero-write reuse;
- bound authorization to only the canonically derived first target and exact
  mode/order/topology/seed/version/storage/configuration/capacity/source/
  empty-cluster digests, kept every join excluded and waiting for health, and
  added fail-closed proof/gate/drift/path/write/redaction/no-process coverage;
- added distinct owner-only initial-seed bootstrap execution binding/execution/
  evidence-entry/evidence/report v1 schemas and local `show` validation, with
  complete context/plan/authorization/current-chain revalidation and canonical
  derivation of the exact target, mode, topology, sole seed, configuration,
  storage, package, variables, source, and anchored command;
- added durable `prepared` then `started` ownership around the sole sensitive,
  exact-one-target, serial-one, check-mode-refused `scylla-bootstrap` fake-runner
  call; `started` consumes both ordinary and narrow authorization without
  rewriting the immutable authorization;
- required strict semantic target/mode and prerequisite parity plus source-bound
  pre-start service revalidation, unmask/start, bounded CQL, hashed Host/ring,
  schema-agreement, and idle-streaming evidence rather than trusting exit zero;
- preserved strict never-joined remask versus possibly-joined node-preservation
  semantics, made every started uncertainty permanent manual-recovery/no-retry/
  restart/destroy/removenode, and added prepared recovery plus exact completed
  zero-call re-entry;
- added fake-only coverage for success, never-joined/remasked and joined/
  uncertain failures, malformed/timeout/scope/drift/path/persistence refusal,
  no retry, no unrelated calls, redaction, and owner-only modes;
- added owner-only operation-bound Scylla-health execution, evidence, checkpoint,
  and report v1 schemas plus local `show` validation after successful
  initial-seed bootstrap;
- scoped current membership to the exact succeeded bootstrap prefix, kept
  desired waiting nodes separate, and required strict hashed Host-ID, UN
  topology, schema, streaming, service/API/CQL, storage, and version evidence
  rather than trusting exit zero;
- reconciled the immutable bootstrap plan through a separate checkpoint,
  preserving current health, target-absence, topology/schema, streaming, and
  unknown/not-performed policy facts without silently advancing a join;
- made every started health uncertainty permanent manual-recovery/no-retry,
  added exact zero-process re-entry and fake-only success/failure/drift/path/
  redaction coverage, and kept the common journal and prior artifacts
  byte-for-byte unchanged at `IN_PROGRESS/VERIFY`; join authorization/execution,
  finalization, CLI, and public wiring remain unavailable;
- added independently versioned owner-only first-join safety context, evidence,
  reconciliation, and report v1 contracts with local `show` validation,
  immutable exact reuse, and no subprocess, authorization, execution, or
  journal mutation;
- bound the exact first waiting `join-existing` target, current survivor set,
  topology, health, configuration, storage, source, and one normalized current
  independent capacity proof; failed, unknown, stale, and mismatched required
  evidence fail closed while later joins remain waiting;
- applied the PLAN-defined initial-deploy policy: capacity remains required,
  while replication, quorum, and Manager backup policy are explicitly
  `not-applicable` stronger removal/replacement gates rather than silently
  passed or over-required;
- added distinct immutable owner-only first-join sensitive authorization
  proof/record/report v1 schemas and local `show` validation at
  `operations/<operation-uuid>.ansible-deploy-scylla-join-authorization.json`,
  with exact full-chain reproduction through initial bootstrap, current health,
  and all join-safety records;
- derived only the reconciled sequence-two `join-existing` target plus current
  survivor/active-seed, topology/schema/membership, package/storage/
  configuration/capacity/source/safety digests; excluded every later waiting
  join; and refused every failed, unknown, stale, drifted, or mismatched
  required gate;
- required ordinary interactive or `cli-yes` approval plus a separate exact
  target/mode/scope acknowledgement, kept `cli-yes` alone insufficient,
  refused destructive proof, persisted unconsumed `0600` state, and left
  execution, public wiring, prior artifacts, and the common VERIFY journal
  unchanged with zero process calls;
- added distinct owner-only first-join execution/evidence/report v1 contracts
  with local `show` validation and exact full-chain revalidation through the
  immutable bootstrap, initial-seed, current-health, join-safety,
  authorization, source, catalog, and VERIFY-journal records;
- derived and invoked only the authorized reconciled sequence-two
  `join-existing` target through hash-checked exact-one-target, serial-one,
  check-mode-refused `scylla-bootstrap`, with durable prepared/started intent
  and ordinary plus narrow authorization consumption at `started`;
- required strict target, mode, prerequisite, pre-start, source/command/
  variable-intent, CQL, membership, topology, schema, and streaming semantics
  beyond exit zero; kept persisted evidence and reports free of addresses, raw
  Host IDs, provider IDs, seed/configuration values, output, commands,
  variables, environment, protected paths, credentials, and secrets;
- made every post-start crash, timeout, interruption, nonzero/unreachable/
  malformed result, drift, or persistence failure permanent
  manual-recovery/no-retry; added exact zero-process success re-entry and kept
  later joins, prior artifacts, public wiring, and the common VERIFY journal
  unchanged;
- added immutable owner-only post-first-join health execution, evidence,
  reconciliation, and report v1 contracts with local `show` validation and
  exact full-chain revalidation through successful sequence-two execution;
- selected a fresh exact complete-current-set `scylla-health` checkpoint
  because the pre-join checkpoint covers only the initial seed and bootstrap
  success is not cluster-health evidence; reused the existing controlled
  service, payload builder, source validation, and strict parser;
- required hashed exact initial-seed-plus-sequence-two membership, all members
  Up Normal, cross-view topology/schema agreement, idle streaming,
  service/API/CQL readiness, and current storage/configuration/source
  provenance, with durable started intent and permanent no-retry after
  uncertainty;
- reconciled only the two completed bootstrap steps and at most the immediate
  next join, preserving replication/backup `not-performed` and quorum/capacity
  `unknown` as blockers; kept all later joins waiting, supported
  reconciliation-only prefix recovery and exact zero-call/zero-write re-entry,
  and left prior artifacts, public wiring, `UPSTREAM_TODO.md`, and the VERIFY
  journal unchanged;
- added independently versioned owner-only sequence-three join-safety context,
  evidence, reconciliation, and report v1 contracts with local `show`
  validation and exact full-chain revalidation through terminal sequence-two
  execution and fresh post-first-join health;
- required the exact contiguous sequence-three target, current two-member
  healthy survivor and active-seed scope, target absence and provenance,
  current trust/routes/readiness, no competing operation, and independent
  backup-policy, capacity, quorum, and replication proofs; unknown, failed,
  missing, duplicate, stale, or drifted gates remain blockers;
- allowed only exact all-pass evidence to mark sequence three
  `authorization-required`, kept every later join waiting, added exact-prefix
  recovery and zero-write reuse, and left authorization, execution, prior
  artifacts, public wiring, `UPSTREAM_TODO.md`, and the VERIFY journal
  unchanged;
- added a distinct immutable owner-only sequence-three sensitive join
  authorization proof/record/report v1 contract with local `show` validation
  at
  `operations/<operation-uuid>.ansible-deploy-scylla-sequence-three-join-authorization.json`;
- canonically reproduced the complete sequence-two execution, post-join health,
  sequence-three safety, and current infrastructure/Ansible provenance chain;
  bound only the exact reconciled sequence-three target plus all required
  membership, topology, health, capacity, replication, quorum, backup, source,
  and safety identities through redacted counts, enums, and digests;
- required ordinary interactive or `cli-yes` approval plus a separate exact
  target/mode/scope acknowledgement, kept `cli-yes` alone insufficient, refused
  destructive proof, excluded every later waiting join, and retained
  unconsumed authorization with execution unavailable, zero-write reuse, no
  process/public wiring, and an unchanged VERIFY journal;
- added distinct owner-only sequence-three join execution, semantic-evidence,
  and report v1 contracts with local `show` validation and exact full-chain
  revalidation through sequence-two success, post-first-join health,
  sequence-three safety/authorization, source/catalog, and current
  infrastructure/Ansible provenance;
- derived and invoked only authorized reconciled sequence three through the
  hash-checked exact-one-target, serial-one, check-mode-refused
  `scylla-bootstrap` source, with durable prepared/started intent and ordinary
  plus narrow authorization consumption at `started`;
- required strict target/mode/prerequisite/pre-start/source/command/provenance,
  CQL, membership, topology, schema, and streaming semantics beyond exit zero,
  persisted redacted semantic evidence before terminal success, and kept every
  later join waiting;
- made every post-start crash, timeout, interruption, nonzero/unreachable/
  malformed result, state drift, or persistence failure permanent manual-
  recovery/no-retry; allowed only prepared-before-invocation recovery and exact
  zero-process/zero-write success re-entry; and left prior artifacts,
  post-sequence-three health, public wiring, `UPSTREAM_TODO.md`, and the common
  VERIFY journal unchanged;
- added distinct owner-only post-sequence-three join health execution,
  evidence, reconciliation, and report v1 contracts with local `show`
  validation and exact full-chain revalidation through terminal sequence-three
  execution with consumed ordinary and narrow proofs;
- reused the existing hash-checked read-only `scylla-health` source, controlled
  service, payload builder, and strict parser for the exact three-member
  complete current set; required unique hashed membership, all members Up
  Normal, cross-view topology/schema agreement, idle streaming,
  service/API/CQL readiness, and current storage/configuration/source
  provenance beyond exit zero or bootstrap success;
- retained backup/replication as `not-performed` and capacity/quorum as
  `unknown`, recorded durable started intent, made every post-start uncertainty
  permanent manual-recovery/no-retry, supported reconciliation-only recovery
  and exact zero-process/zero-write re-entry, and left prior records plus the
  VERIFY journal unchanged; and
- reconciled only exact sequence-three health, leaving any later planned join
  waiting for its own separately versioned safety context or reporting bounded
  bootstrap-sequence-complete/next-step-not-required truth when no later plan
  step exists; no later safety, authorization, execution, finalization,
  public/CLI wiring, or upstream-role workaround was added;
- added generic owner-only later-join safety context, evidence, reconciliation,
  and report v1 contracts that derive the first unfinished immutable
  bootstrap-plan `join-existing` sequence `>=4` from the canonical contiguous
  completed prefix and latest fresh complete-set health rather than accepting
  caller-selected sequence or target input;
- bound the exact healthy prefix, target absence/provenance, route/trust/
  readiness, source/catalog/journal, competing-operation truth, and independent
  capacity/replication/quorum/backup proofs; unknown gates block, and only the
  derived immediate sequence may become `authorization-required` while every
  later step remains waiting;
- returned strict write-free `not-required` for a completed bootstrap sequence,
  supported exact-prefix recovery and zero-write reuse, rejected changed
  sequence/proof/prefix/provenance conflicts, and added local `show` validation
  without authorization, execution, health calls, journal transition,
  public/CLI wiring, or an upstream-role workaround;
- added a generic immutable owner-only later-join sensitive authorization
  proof/record/report v1 contract with local `show` validation in immutable
  sequence-keyed operation records;
- derived only the exact first unfinished reconciled `join-existing` sequence
  `>=4`, bound its completed prefix, order, target, membership/topology/schema/
  streaming, package/storage/configuration/capacity, independent policy,
  source, and safety identities through bounded redacted values and digests,
  and kept every later step waiting and excluded;
- required ordinary interactive or `cli-yes` approval plus a separate exact
  digest-only target/mode/sequence/scope acknowledgement, kept `cli-yes` alone
  insufficient, refused destructive proof, and returned write-free
  `not-required` with no accepted proof after bootstrap completion; and
- kept generic later-join authorization unconsumed with execution unavailable,
  exact zero-write reuse, fail-closed proof/scope/gate/prefix/provenance drift,
  no process/health/CLI/public wiring, no upstream-role workaround, and an
  unchanged VERIFY journal;
- added generic owner-only later-join execution/evidence/report v1 contracts
  that derive and bind only the canonically authorized first unfinished
  `join-existing` sequence `>=4`, with no per-node module or caller-selected
  sequence, target, order, scope, variables, command, result, or retry input;
- durably recorded pre-invocation `prepared` and approval-consuming `started`
  states around one exact hash-checked `scylla-bootstrap` call, required strict
  semantic evidence before terminal success, and made every post-start
  uncertainty manual-recovery/no-retry while preserving exact prepared and
  completed re-entry behavior; and
- changed the unreleased generic later-join safety, authorization, execution,
  and evidence families to immutable sequence-keyed paths so sequence five and
  later can coexist with sequence-four history without overwrite;
- added generic sequence-keyed post-later-join complete-set health execution,
  semantic evidence, and reconciliation for exact successful sequences
  `>=4`, reusing the hash-checked read-only `scylla-health` boundary and strict
  complete-membership/topology/schema/streaming/readiness validation; and
- kept later joins waiting for separate fresh complete-set health and safety,
  made started health uncertainty manual-recovery/no-retry, left the VERIFY
  journal and prior records unchanged, and added redacted local `show`
  validation without CLI/public wiring, live execution, or a new upstream-role
  workaround;
- added an immutable post-bootstrap deploy-mapping reconciliation companion
  that validates every contiguous terminal-success bootstrap step plus the
  final sequence-appropriate complete-set health family, proves the historical
  21-position mapping unchanged, and resolves only its explicit unmodeled
  bootstrap boundary;
- bound that final strict health evidence to mapped `scylla-health` and
  advanced only immediate `manager-server` to authorization-required while
  retaining unknown/not-performed replication, backup, quorum, and capacity
  truth, zero-write re-entry, unchanged VERIFY journal state, and redacted
  local `show` validation without public execution wiring;
- added immutable internal authorization for that exact mapped
  `manager-server` instance, deriving its sole manager target and Ubuntu 24.04/
  Manager 3.12 install-only intent from canonical state, requiring ordinary
  interactive or PLAN-permitted `cli-yes` approval, refusing destructive and
  narrow proofs, and retaining unconsumed, execution-unavailable, redacted,
  zero-write-reusable evidence with local `show` validation;
- added the corresponding generation-guarded internal exact execution and
  immutable-prefix semantic-evidence owner, deriving the sole manager target,
  Manager 3.12 install-only payload, source, variables, and anchored command
  from canonical state, consuming authorization at durable `started`, and
  accepting only strict installed/no-change, masked/inactive, no-backend,
  no-configuration, no-setup, no-registration, no-task, and no-start evidence;
- made every uncertain started Manager-server outcome manual-recovery/no-retry,
  preserved exact pre-invocation prepared recovery and zero-process/zero-write
  success re-entry, kept the VERIFY journal/bridge/plans unchanged, and added
  redacted local `show` validation without CLI/public wiring or an
  upstream-role workaround;
- added immutable internal post-`manager-server` reconciliation that requires
  exact consumed terminal-success Manager 3.12 install evidence, preserves the
  historical 21-position mapping, marks only mapped `manager-server`
  evidence-bound succeeded, and evaluates only the immediate next active gate;
- kept that continuation process-free and authorization-free, made exact
  re-entry zero-write and conflicts fail closed, retained the VERIFY journal
  and prior artifacts unchanged, and added bounded redacted local `show`
  validation without a new upstream-role workaround;
- added immutable internal ordinary authorization for the exact mapped
  `monitoring-stack` step exposed by post-Manager reconciliation, deriving the
  sole monitoring target, Ubuntu 24.04 architecture, digest-pinned official
  Scylla Monitoring 4.16.0 archive/component/source provenance, and
  archive-install-only policy from canonical state;
- required interactive or PLAN-permitted `cli-yes`, refused destructive and
  narrow proof, kept Docker/image-pull/Compose/auth/targets/containers/start/
  public-bind/Manager/Scylla/secrets actions forbidden, and retained
  unconsumed execution-unavailable zero-write-reusable state with redacted
  local `show` validation, unchanged VERIFY history, no process or public/CLI
  wiring, and no upstream-role workaround;
- added the corresponding generation-guarded internal exact execution and
  immutable-prefix semantic-evidence owner, deriving the sole monitoring
  target, digest-pinned Scylla Monitoring 4.16.0 archive/component/source
  provenance, install-only payload, variables, and anchored command from
  canonical state, then consuming authorization at durable `started`;
- accepted only strict installed/no-change, Docker-disabled/inactive,
  listen-policy-not-started evidence with Docker installation/image pull,
  Compose/auth/target generation, containers/service starts, public binds,
  Manager registration, Scylla start, and secrets all unperformed;
- made every uncertain started monitoring-stack outcome manual-recovery/no-
  retry, preserved exact pre-invocation prepared recovery and zero-process/
  zero-write success re-entry, kept the VERIFY journal/authorization/
  post-Manager reconciliation/plans unchanged, and added redacted local `show`
  validation without CLI/public wiring or an upstream-role workaround;
- added immutable internal post-`monitoring-stack` reconciliation that requires
  exact consumed terminal success, canonical-target Scylla Monitoring 4.16.0
  archive/component/source/command provenance, installed/no-change,
  disabled/inactive Docker, listen-policy-not-started evidence, and no Docker,
  image-pull, Compose, auth, target, container, service-start, public-bind,
  Manager, Scylla, or secret action;
- preserved the historical 21-position mapping, marked only mapped
  `monitoring-stack` evidence-bound succeeded, evaluated only the immediate
  next active gate without health/readiness/listener inference, kept exact
  re-entry zero-write and conflicts fail-closed, and retained the VERIFY
  journal/prior artifacts plus bounded redacted local `show` behavior without
  process calls, authorization, public wiring, or an upstream workaround;
- added immutable internal ordinary authorization for exact mapped position 16
  `manager-agent`, deriving the complete current Scylla stable-ID scope,
  Ubuntu 24.04 architecture, current Scylla-install provenance, and exact
  Manager 3.12 package/repository/authenticated-key/source/command intent from
  canonical state;
- required interactive or PLAN-permitted `cli-yes`, refused destructive and
  narrow proofs, kept configuration/token/helper/reachability/start actions
  forbidden or not-performed, and persisted only an unconsumed owner-only
  bounded redacted authorization validated by local `show` without execution,
  journal changes, CLI/public wiring, or an upstream workaround;
- added the corresponding generation-guarded internal exact execution and
  immutable-prefix semantic-evidence owner, deriving the complete ordered
  Scylla stable-ID scope, exact Manager 3.12 agent package provenance,
  install-only payloads, and anchored commands from canonical state and
  consuming the whole authorization at the first durable `started` attempt;
- accepted only strict installed/no-change evidence with the agent disabled/
  inactive and configuration/token/helper/reachability/start behavior absent
  or not performed, made every uncertain started result permanently
  manual-recovery/no-retry, preserved prepared recovery and zero-process/
  zero-write completed re-entry, and added redacted local `show` validation
  without changing the VERIFY journal, reconciling a next stage, adding public
  wiring, or introducing an upstream workaround;
- added immutable internal post-`manager-agent` reconciliation that requires
  exact consumed terminal success and complete unique ordered Manager 3.12
  package/service semantic evidence for every authorized Scylla stable ID;
- preserved the historical 21-position mapping, marked only mapped
  `manager-agent` evidence-bound succeeded, evaluated only the immediate next
  active gate, and kept exact re-entry zero-write, conflicts fail-closed, the
  VERIFY journal/prior artifacts unchanged, and local `show` bounded/redacted
  without process calls, authorization, public wiring, or an upstream
  workaround;
- added immutable internal ordinary authorization for exact mapped position 17
  `monitoring-agent`, deriving the complete canonical Scylla stable-ID scope,
  Ubuntu 24.04 architecture, current Scylla-install provenance, and exact
  ScyllaDB 2026.2 `scylla-node-exporter` package/repository/authenticated-key/
  source/variable/command intent from post-Manager-agent reconciliation;
- required interactive or PLAN-permitted `cli-yes`, refused destructive and
  narrow proofs, kept the exporter disabled/inactive with listen policy
  `not-started`, and left configuration, process-exporter, stack/target
  generation, Manager registration, exporter/Scylla startup, listeners, and
  secrets forbidden or not performed;
- persisted only an unconsumed execution-unavailable owner-only bounded
  authorization with exact zero-write reuse and redacted local `show`
  validation, leaving the VERIFY journal/prior records unchanged without
  execution, CLI/public wiring, or an upstream workaround;
- added the corresponding generation-guarded internal exact execution and
  immutable-prefix semantic-evidence owner, deriving the complete ordered
  Scylla stable-ID scope, exact ScyllaDB 2026.2 node-exporter package
  provenance, install-only/no-listen payloads, and anchored commands from
  canonical state and consuming the whole authorization at the first durable
  `started` attempt;
- accepted only strict installed/no-change evidence with the exporter
  disabled/inactive, listen policy `not-started`, and configuration,
  process-exporter, stack, targets, registration, startup, listener, and secret
  behavior absent or not performed; made every uncertain started result
  permanently manual-recovery/no-retry; preserved prepared recovery and exact
  zero-process/zero-write completed re-entry; and added redacted local `show`
  validation without changing the VERIFY journal, reconciling a next stage,
  adding public wiring, or introducing an upstream workaround;
- added immutable internal post-`monitoring-agent` reconciliation that requires
  exact consumed terminal success and complete unique ordered ScyllaDB 2026.2
  exporter package/service/listen-policy evidence for every authorized Scylla
  stable ID;
- preserved the historical 21-position mapping, marked only mapped
  `monitoring-agent` evidence-bound succeeded, evaluated only the immediate
  next active gate, and kept exact re-entry zero-write, conflicts fail-closed,
  the VERIFY journal/prior artifacts unchanged, and local `show` bounded/
  redacted without process calls, target generation, health inference, public
  wiring, or an upstream workaround;
- added immutable internal mapped `monitoring-targets` authorization that
  exactly reproduces the canonical chain through post-`monitoring-agent`
  reconciliation, requires mapping position 18 for the single monitoring
  stable ID, validates current Ubuntu 24.04/base-OS, Monitoring 4.16.0 stack,
  Manager-server, Manager-agent, and Monitoring-agent evidence, and rebuilds
  the deterministic official four-file target intent from canonical RFC 1918
  inventory;
- required ordinary interactive or PLAN-permitted `cli-yes` approval, refused
  destructive and narrow proofs, retained only bounded values and digests in
  the owner-only immutable record, kept exact same-proof reuse zero-write, and
  added local `show` validation without target-file writes, process calls,
  execution state, journal changes, finalization, public wiring, or an upstream
  workaround;
- added the generation-guarded internal mapped `monitoring-targets` execution
  and immutable-prefix semantic-evidence owner, deriving the single canonical
  monitoring target, deterministic official four-file intent, complete RFC
  1918 identity/count sets, hash-checked source, variables, and anchored command
  from current canonical state and consuming authorization at durable
  `started`;
- accepted only strict Monitoring 4.16.0 generated/no-change file-set/content/
  identity/provenance evidence with listen policy `not-started`, scrape
  readiness `not-performed`, and service/container/exporter/auth/public-bind/
  Compose/secret actions absent; made uncertain started outcomes permanently
  manual-recovery/no-retry; preserved prepared recovery and exact
  zero-process/zero-write completed re-entry; and added bounded local `show`
  validation without changing the VERIFY journal, reconciling later work,
  starting services, testing scrapes, exposing a UI, adding public wiring, or
  introducing an upstream workaround;
- added immutable internal post-`monitoring-targets` reconciliation that
  requires exact consumed terminal success and one complete unique Monitoring
  4.16.0 generated/no-change four-file intent result for the canonical
  monitoring stable ID, with exact source/command/provenance and every
  forbidden service/container/auth/public-bind/secret action absent;
- preserved the historical 21-position mapping, marked only mapped
  `monitoring-targets` evidence-bound succeeded, and evaluated only immediate
  sensitive `manager-tasks`; retained its exact blockers because the explicit
  action remains unmodeled and its source is validation-only while Manager is
  inactive, unregistered, and without a configured backend, without inferring
  backup/repair readiness or invoking `sctool`;
- kept exact re-entry zero-write, conflicts fail-closed, the VERIFY
  journal/prior artifacts unchanged, and local `show` bounded/redacted without
  process calls, authorization/execution, Manager start/configuration/
  registration, finalization, public wiring, or an upstream workaround;
- added separate immutable, owner-only Manager-activation context and plan
  companions that reload the exact chain through post-`monitoring-targets`,
  derive the canonical Manager server and complete Scylla agent scope, and
  preserve the historical 21-position mapping unchanged;
- modeled ordered backend configuration, Manager service activation/readiness,
  cluster-registration/auth-token handoff, and mapped `manager-tasks`
  action/context boundaries without inventing executable sources: the first
  three remain source-unavailable and all remain authorization-required,
  evidence-required, blocked, and not-performed;
- kept install-only Manager server/agent evidence from implying backend,
  service, registration, token, reachability, or task readiness, and retained
  `manager-tasks-action-unmodeled` because deploy provides no deterministic
  explicit action rather than selecting the validation source's default;
- added full in-memory construction, context-first exact-prefix recovery,
  zero-write reuse, conflict/tamper/drift refusal, bounded local `show`
  validation, and redacted reports while leaving the VERIFY journal and prior
  artifacts unchanged;
- added immutable internal Manager backend-configuration context and plan
  companions that revalidate the exact activation plan, final Scylla health/
  topology, Manager install evidence, and complete current local provenance
  while preserving the historical mapping and VERIFY journal;
- adopted versioned Manager backend policy
  `deploy-scylla-vms.manager-backend-local-one-node-policy/v1`, selecting the
  official recommended one-node ScyllaDB backend on the Manager VM, forbidding
  the managed data cluster and CQL network ingress, fixing loopback-only port
  9042 contact and ScyllaDB 2026.2 compatibility, and requiring no backend
  credentials/TLS secrets while preserving future environment-only
  Manager-agent token policy;
- resolved only the typed backend-mode blocker while retaining explicit
  package availability, storage/tuning/capacity, setup, configuration,
  schema/keyspace, recovery, and mutating-source blockers;
- added source-available read-only `manager-backend-preflight`, Manager-only,
  exact-one-target, serial-one, fatal, and check-mode-safe, with exact current
  Ubuntu 24.04/base-OS, Manager 3.12 install, activation/backend plan,
  inventory/trust/readiness, and source provenance gates;
- limited host inspection to bounded OS/architecture, CPU/memory/root
  capacity, approved-mount counts, fixed local Scylla/Manager package and
  service state, reboot requirement, and loopback availability; explicitly
  excluded repository queries, arbitrary environment/process/config/device
  collection, cloud metadata, network/CQL/schema access, and mutation;
- added strict redacted
  `deploy-scylla-vms.ansible-manager-backend-preflight/v1` payload/result
  parsing, packaged playbook/role/module provenance, source hashing, fixtures,
  and focused success/refusal/check-mode/redaction/provenance tests; retained
  unresolved design blockers even when host evidence is ready and kept backend
  operational readiness `not-performed`;
- kept the distinct mutating backend boundary source-unavailable,
  blocked-before-authorization, and not-performed because `manager-server` is
  install-only, `manager-tasks` is validation-only, and no reviewed backend
  configuration source exists; retained context-prefix recovery, zero-write
  reuse, fail-closed conflict/tamper/drift handling, and bounded local `show`
  validation;
- added the operation-bound Manager backend-preflight execution owner, which
  revalidates the complete local-one-node planning and current controller/
  toolchain chain, derives the exact Manager target and fixed read-only intent,
  durably records `started`, and invokes only the hash-checked exact-target,
  serial-one, check-mode-safe source through the controlled runner;
- added independently versioned owner-only execution and immutable-prefix
  semantic-evidence records with strict target/role/OS/architecture/source/
  command/provenance parity, bounded redacted host evidence, explicit
  not-performed actions, and permanent manual-recovery/no-retry handling for
  every started uncertainty, process/result failure, mismatch, drift, or
  post-call persistence failure;
- added immutable backend-preflight reconciliation and local `show` validation,
  preserving package availability, storage/tuning suitability, exact capacity
  policy, setup behavior, schema/keyspace policy, recovery, and mutating source
  as explicit unknowns/blockers while backend readiness remains not-performed;
  exact completed re-entry is zero-process/zero-write and the VERIFY journal
  and prior records remain unchanged with no mutation authorization,
  configuration write, service start, registration, task action, public wiring,
  dependency change, or upstream workaround;
- added immutable internal Manager local-backend installation context and plan
  companions that revalidate exact preflight reconciliation plus current
  desired/observed Manager storage, preserve the historical mapping and VERIFY
  journal, support context-prefix recovery and zero-write reuse, and fail
  tamper, drift, or ambiguous history closed;
- safely bind the dedicated Manager Block Volume through redacted digests when
  it is exactly identifiable, forbid root/boot or generic-free-space fallback,
  and retain `dedicated-backend-storage-unmodeled` when it is absent or
  ambiguous;
- modeled package install, storage allocation/preflight/preparation/postcheck,
  local configuration/tuning, one-node bootstrap/start/health, Manager backend
  file configuration, and schema/keyspace creation/verification as nine
  separate not-performed boundaries; the package step is source-available and
  can become evidence-ready for ordinary authorization while the remaining
  eight sources stay blocked and unavailable;
- reused only authenticated ScyllaDB 2026.2 package repository/key references
  while retaining exact package-set/availability, capacity, storage/tuning,
  service-order, configuration/schema, recovery, and `scyllamgr_setup` gates;
  Scylla-role owners remain contract-incompatible;
- added source-available `manager-backend-local-install`, a Manager-only,
  exact-one-target, serial-one, fatal, check-mode-preview package contract for
  the selected local-one-node backend that revalidates the immutable
  installation context/plan, preflight reconciliation, identified dedicated
  storage, Manager/base-OS, observation/inventory/trust, and packaged-source
  chain;
- reused only the reviewed exact seven-package ScyllaDB 2026.2 package set and
  authenticated vendored signing-key/repository provenance, without invoking
  the upstream role or importing the Scylla-role storage prerequisite;
- suppressed maintainer-script startup, masked/stopped `scylla-server` before
  package work, left it masked/inactive, and added strict redacted
  `deploy-scylla-vms.ansible-manager-backend-local-install/v1` parsing for
  installed/no-change/non-predictive-check/failure evidence with bound package,
  repository, key, source, and command-policy digests;
- kept setup, tuning, storage/filesystem/mount mutation, configuration, CQL/
  schema/keyspace work, Manager configuration/registration/tasks, token work,
  and service enable/start false or not-performed;
- added the internal operation-bound
  `deploy-scylla-vms.ansible-deploy-manager-backend-local-install-authorization/v1`
  owner, which reproduces the exact current package plan and complete
  preflight/Manager/base-OS/local-state/source/catalog/package provenance chain,
  accepts only ordinary interactive or PLAN-permitted `cli-yes` approval,
  refuses destructive/narrow proof and stale or drifted plans, and persists an
  immutable redacted unconsumed authorization with exact zero-write reuse;
- added the operation-bound Manager local-backend package execution owner with
  generation-guarded
  `deploy-scylla-vms.ansible-deploy-manager-backend-local-install-execution/v1`
  and immutable-prefix semantic-evidence v1 companions, exact prepared/start
  authorization consumption, one hash-checked exact-target controlled call,
  and zero-process/zero-write completed re-entry;
- required strict installed/no-change package, repository, authenticated-key,
  source, command, dedicated-storage, masked/inactive-service, and forbidden-
  action parity; every started timeout, interruption, process/output/result
  failure, semantic mismatch, drift, or persistence uncertainty is permanent
  manual-recovery/no-retry;
- kept the authorization, installation plans, and `IN_PROGRESS/VERIFY` journal
  unchanged, added bounded local-show validation and fake-only execution/
  refusal/recovery/tamper coverage, and added no CLI/public wiring, dependency
  change, live execution, or upstream workaround;
- added immutable owner-only post-Manager-local-package reconciliation that
  revalidates the complete policy/preflight/plan/authorization/execution/
  evidence and current local-state chain, requires exact consumed terminal
  success, and marks only package installation evidence-bound succeeded;
- preserved all nine installation boundaries and every original identity
  digest, derived only immediate `local-storage-allocation`, and retained its
  unavailable Manager-local source/contract, unknown capacity policy, and
  incompatible Scylla-role storage owner as blockers without advancing later
  storage, tuning, setup, configuration, schema, or recovery work;
- added exact zero-write reuse, conflict/tamper/drift refusal, bounded local
  `show` validation, and focused fake-only tests while keeping prior records and
  the `IN_PROGRESS/VERIFY` journal unchanged and the reconciliation immutable;
- added independently versioned immutable owner-only Manager-backend storage
  allocation context and plan companions that revalidate the complete
  post-package, backend-plan, Manager-target, desired/Terraform input/
  observation/inventory/trust/readiness, source/catalog, and VERIFY-journal
  chain without rewriting prior records;
- restricted allocation to one exact dedicated Manager-role Block Volume bound
  by stable/provider identity and the Terraform storage manifest; root/boot,
  local NVMe, arbitrary attachment, path/order, generic-free-space, and shared
  Scylla-role fallback remain forbidden, while missing, ambiguous, or path-only
  identity creates no discovery scope;
- retained capacity policy as `unknown` and adequacy as `not-evaluated`, exposed
  only bounded requested/observed GiB/count/backend states and redacted identity
  digests, and added context-prefix recovery, exact zero-write reuse,
  conflict/tamper/drift refusal, and local `show` validation;
- added source-available read-only `manager-backend-storage-discover`,
  Manager-only, exact-one-target, serial-one, fatal, and check-mode-safe, with
  strict Terraform-manifest correlation through bounded block/mount/signature/
  holder/ownership/topology facts and non-path guest identities;
- added strict redacted
  `deploy-scylla-vms.ansible-manager-backend-storage-discovery/v1`
  payload/result parsing, packaged role/module provenance and source hashing,
  registry/service integration, fixtures, and focused success/refusal/
  ambiguity/root-fallback/redaction/check-mode/provenance tests;
- kept raw paths/serials/UUIDs, addresses, provider IDs, commands, output,
  environment, credentials, and secrets out of evidence; kept every write,
  wipe, partition, RAID/filesystem, mount/fstab, configuration/service, and CQL
  action absent;
- added operation-bound Manager-backend storage discovery execution with an
  exact canonical API, full allocation/package/current-state revalidation,
  derived sole-target manifest-bound invocation, durable started intent,
  generation-guarded execution, and immutable-prefix semantic evidence;
- made every started process uncertainty, failure, malformed result, semantic
  mismatch, drift, or persistence uncertainty permanent manual-recovery/
  no-retry, while exact complete re-entry performs no process call or write;
- added immutable Manager-backend storage discovery reconciliation that marks
  only strict discovered evidence succeeded, leaves bounded blocked evidence
  blocked, and retains capacity adequacy unknown, storage preflight/preparation
  unavailable, wipe safety not evaluated, and owned-noop not inferred;
- added local `show` validation and focused success/refusal/tamper/drift/
  no-retry/re-entry/ambiguity/redaction/reconciliation tests while preserving
  all prior records and the unchanged `IN_PROGRESS/VERIFY` journal; and kept
  authorization, storage mutation/preflight/preparation, configuration/service
  work, CLI/public wiring, dependency changes, live-system actions, and
  upstream-role workarounds absent;
- added immutable owner-only Manager-backend dedicated-storage preflight
  context and plan companions that revalidate the complete local-one-node,
  package, allocation, successful discovery, exact Manager target, desired/
  Terraform manifest, hashed guest-device, source/catalog, and VERIFY-journal
  chain without accepting caller device/path/action/layout/capacity/command/
  variable/free-text input;
- approved only a single whole dedicated Block Volume with XFS, fixed
  `/var/lib/scylla` ownership, required fstab/mount intent, and a one-node
  Manager-backend marker; kept RAID, partitions, local NVMe, root/boot fallback,
  arbitrary attachments, and shared Scylla-role storage forbidden;
- required desired, observed, and discovered size equality as policy
  conformance while retaining operational capacity sufficiency as
  operator-policy-bound `not-proven`;
- added source-available read-only `manager-backend-storage-preflight`,
  Manager-only, exact-one-target, serial-one, fatal, and check-mode-safe, with
  strict `owned-noop`/`prepare-required`/`blocked` classification, exact bounded
  actions, foreign-signature refusal, and separately reported wipe requirement;
- added strict redacted
  `deploy-scylla-vms.ansible-manager-backend-storage-preflight/v1`
  payload/result parsing, packaged playbook/role/module provenance, catalog/
  service/source/show integration, fixtures, and focused planning, success,
  refusal, check-mode, redaction, and provenance tests;
- kept every write, wipe, partition, RAID/filesystem, mount/fstab/marker,
  configuration/service, setup, and CQL action absent;
- added operation-bound Manager-backend storage-preflight execution with exact
  canonical inputs, full current-chain revalidation, derived one-target policy/
  manifest/discovery variables, hash-checked anchored invocation, durable
  started intent, generation-guarded execution, and immutable semantic
  evidence;
- made every started crash, timeout, process/output failure, malformed or
  conflicting result, drift, and post-call persistence uncertainty permanent
  manual-recovery/no-retry, while exact completed re-entry is zero-process and
  zero-write;
- added immutable reconciliation that marks only exact preflight evidence
  succeeded, keeps `owned-noop` not-required and blocked dispositions blocked,
  derives only exact `prepare-required` stable-ID/device-set/preparation-intent
  scope, and retains a separate wipe-required subset and scope digest;
- retained capacity sufficiency as `not-proven`, exposed only exact
  `prepare-required` scope as `evidence-ready-authorization-required`, and
  added source-available destructive `manager-backend-storage-prepare` for one
  exact whole-device XFS Block Volume, stable-UUID fstab, `/var/lib/scylla`
  mount, root ownership/mode, and Manager ownership marker;
- required immediate identity/signature/ownership/busy/root/boot/mount/fstab
  revalidation, separate digest-bound wipe consent, explicit mutation/first-
  irreversible-step/recovery evidence, and strict redaction while forbidding
  RAID/LVM/NVMe/root fallback and package/tuning/configuration/schema/service
  actions;
- kept Manager-local preparation authorization/execution ownership unavailable,
  preserving the VERIFY journal and all prior records while adding local
  `show` validation and
  focused success/refusal/tamper/drift/no-retry/re-entry/disposition/wipe/scope
  tests; and added no authorization, mutation, postcheck, configuration/
  service work, CLI/public wiring, dependency change, live-system action, or
  upstream-role workaround. The next slice is the operation-bound
  Manager-local storage-preparation authorization owner;
- added stable foundation error/exit-code mapping and minimal secret redaction;
  and
- established Ruff, mypy, pytest, CI checks, and local unit coverage for the
  implemented boundaries.

The other 10 operation workflows remain deliberately unimplemented and return
exit `10` after complete local request validation without creating state.
Malformed or incomplete requests return exit `2`. Config loading and
desired-spec compilation are read-only and do not make deploy operational. This
release does not include OCI access, a public mutating Ansible operation
workflow, provider observation refresh, CLI-wired SSH validation, or live
`show` checks. The process, Terraform, observation, reconciliation, inventory,
SSH trust/routing, readiness, and Ansible execution boundaries are fake-tested.
`check-jump-hosts` is the only CLI path that invokes Ansible/SSH, and only after
complete local readiness under a non-mutating lock; no CLI path exposes apply
or destroy. State initialization and persistence remain internal explicit APIs
and are not invoked by CLI parsing, local `show`, or unimplemented operations.
The packaged, provider-schema-validated source includes image selection,
network/security, compute, storage, and complete strict outputs and is now
planning-ready. Provider installation occurs only during explicit local
Terraform initialization; no planning CLI is claimed.
