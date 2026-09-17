# Upstream ScyllaDB Ansible role tracker

## Table of contents

- [Purpose and scope](#purpose-and-scope)
- [Upstream baseline](#upstream-baseline)
- [Contribution and update policy](#contribution-and-update-policy)
- [Status vocabulary](#status-vocabulary)
- [Verified gaps](#verified-gaps)
  - [SAR-001 strict Ubuntu package-only installation boundary](#sar-001-strict-ubuntu-package-only-installation-boundary)
  - [SAR-002 configuration-only role mode](#sar-002-configuration-only-role-mode)
  - [SAR-003 quiescent Scylla service handoff](#sar-003-quiescent-scylla-service-handoff)
- [Needs upstream verification](#needs-upstream-verification)
  - [SAR-C001 Ubuntu 24.04 role support declaration](#sar-c001-ubuntu-2404-role-support-declaration)
- [Examined items that are not upstream-role gaps](#examined-items-that-are-not-upstream-role-gaps)
- [Maintenance checklist for adopting upstream fixes](#maintenance-checklist-for-adopting-upstream-fixes)

## Purpose and scope

This file is the ongoing tracker for verified limitations in the upstream
ScyllaDB Ansible node role that cause this project to maintain a local
workaround. It is not a general project backlog.

An entry belongs here only when all of the following are true:

- the affected behavior is reasonably within the responsibility of the
  upstream `scylladb.scylla_node` role;
- an immutable upstream source revision or official ScyllaDB documentation
  demonstrates the limitation;
- current local implementation files clearly replace, constrain, or guard that
  upstream behavior; and
- removing the local workaround would currently violate a documented project
  boundary.

Terraform, OCI resource handling, inventory and SSH trust, operation journals,
authorization, cluster lifecycle orchestration, Manager, and monitoring are
not upstream node-role gaps merely because this project implements them.

This audit was last performed on 2026-09-20. At that time the upstream
`master` branch still resolved to the pinned commit below.

## Upstream baseline

- Repository:
  [`scylladb/scylla-ansible-roles`](https://github.com/scylladb/scylla-ansible-roles)
- Role: `scylladb.scylla_node`, sourced from the repository's
  [`ansible-scylla-node/`](https://github.com/scylladb/scylla-ansible-roles/tree/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node)
  directory
- Pinned commit:
  [`42592128ff0399be8ffa18dbc985c4b026e7abd0`](https://github.com/scylladb/scylla-ansible-roles/commit/42592128ff0399be8ffa18dbc985c4b026e7abd0)
  from 2026-09-02
- Local pin:
  `scylla_vms/ansible/content/requirements.yml`,
  `scylla_vms/ansible/toolchain.py`, and
  `scylla_vms/ansible/scylla_install.py`
- Project baseline: Ubuntu 24.04, ScyllaDB release line 2026.2, and either OCI
  `amd64` with guest `x86_64` or OCI/guest `aarch64`
- Current package policy: one complete, exact 2026.2 Debian package version;
  `latest`, ranges, prefixes, release candidates, and other release lines are
  refused

Official baseline references:

- [ScyllaDB 2026.2 Ansible integration](https://docs.scylladb.com/manual/branch-2026.2/using-scylla/integrations/integration-ansible.html)
- [ScyllaDB 2026.2 Linux package installation](https://docs.scylladb.com/manual/branch-2026.2/getting-started/install-scylla/install-on-linux.html)
- [ScyllaDB 2026.2 system requirements](https://docs.scylladb.com/manual/branch-2026.2/getting-started/system-requirements.html)

The upstream wiki is not evidence for closing or adding an entry. It may be
useful for discovery, but every claim must be reverified against immutable
source and official documentation.

## Contribution and update policy

When implementation introduces or changes a workaround because of an upstream
ScyllaDB Ansible node-role limitation, update this file in the same change.

For each entry:

1. Keep its stable ID; never renumber an existing entry.
2. Record the status, affected local feature and files, exact upstream
   limitation, local workaround and safety reason, proposed upstream change,
   and removal criteria.
3. Cite immutable upstream commit URLs and source paths. Add official
   version-specific ScyllaDB documentation when it defines the intended
   behavior.
4. Separate an upstream role limitation from stricter project policy. A local
   preference or application-level safety model is not automatically an
   upstream defect.
5. Use `Needs upstream verification` when evidence establishes a question but
   not a shortcoming. Do not promote it to `Open` without new evidence.
6. Move an entry to `Fixed upstream` only after inspecting the exact upstream
   commit that implements the fix. Move it to `Adopted` only after this project
   has pinned or otherwise consumed that fix and passed the required tests and
   live gates.
7. Preserve the entry after adoption as a short historical record of the
   removed workaround and adopted upstream revision.

## Status vocabulary

- `Open` — verified against the current pinned upstream source; no accepted
  upstream fix is known.
- `Proposed upstream` — an upstream issue or pull request has been opened; link
  it without implying acceptance.
- `Upstream in progress` — upstream maintainers have an active accepted or
  reviewed implementation in progress.
- `Fixed upstream` — an immutable upstream commit contains the verified fix,
  but this project has not adopted it.
- `Adopted` — this project consumes the verified upstream fix and has removed
  or reduced the workaround after validation.
- `Won't upstream` — upstream has explicitly declined or scoped out the change;
  retain the evidence and local rationale.
- `Needs upstream verification` — available evidence is insufficient to call
  the item an upstream gap.

## Verified gaps

### SAR-001 strict Ubuntu package-only installation boundary

**Status:** `Open`

**Affected local feature and files**

- `scylla-install`
- `manager-backend-local-install`
- `scylla_vms/ansible/scylla_install.py`
- `scylla_vms/ansible/manager_backend_local_install.py`
- `scylla_vms/ansible/content/playbooks/scylla-install.yml`
- `scylla_vms/ansible/content/playbooks/manager-backend-local-install.yml`
- `scylla_vms/ansible/content/playbooks/roles/manager_backend_local_install/`
- `scylla_vms/ansible/content/playbooks/roles/scylla_install/files/`
- `tests/test_ansible_scylla_install.py`
- `tests/test_ansible_manager_backend_local_install.py`
- `scylla_vms/ansible/deploy_scylla_install_authorization.py`
- `scylla_vms/ansible/deploy_scylla_install_execution.py`

**Upstream limitation and evidence**

The upstream `install_only` variable skips `common.yml`, but it does not select
a narrow package transaction. The pinned
[`tasks/main.yml`](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/main.yml)
still enters the complete OS-specific task file. On Ubuntu/Debian, pinned
[`tasks/Debian.yml`](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/Debian.yml):

- manages keys through `apt_key` and an HKP keyserver;
- downloads repository list files at execution time;
- installs role-selected dependencies and OpenJDK 8;
- removes configured packages;
- can install Manager Agent packages; and
- installs `xfsprogs`.

Pinned
[`tasks/Debian_install.yml`](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/Debian_install.yml)
uses a shell pipeline to discover a matching version and installs the selected
meta-package with downgrade allowed. It does not install and verify the
official complete exact-version package set documented by the
[ScyllaDB 2026.2 package guide](https://docs.scylladb.com/manual/branch-2026.2/getting-started/install-scylla/install-on-linux.html).

**Local workaround and safety reason**

The local Scylla-node and Manager-local-backend playbooks own a vendored,
digest- and fingerprint-verified 2026 public key, an exact
`deb822_repository`, and an allowlisted seven-package transaction. Both refuse
downgrades, use `policy_rc_d: 101`, perform no package removal, Java
installation, unrelated Manager work, storage work, tuning, or runtime
download, and verify every installed version. The Manager-local source adopts
this workaround without reusing the Scylla-role operation identity or
storage-postcheck contract.

This keeps package installation inside the reviewed install phase and prevents
ambient repository, package, and host changes from bypassing operation
authorization or evidence binding.

**Proposed upstream change**

Add an opt-in strict package-only mode that:

- accepts one complete exact package version and an explicit package set;
- supports caller-supplied authenticated keyring and repository definitions
  without `apt_key`, a keyserver, or runtime repository-file download;
- performs no dependency expansion, package removal, Manager installation,
  storage setup, tuning, configuration, or service start;
- refuses downgrades unless separately requested; and
- returns enough normalized package state for callers to verify the exact
  transaction.

**Acceptance criteria for removing the workaround**

- A new immutable upstream commit implements the strict mode without falling
  through to the broad Debian path.
- Source and tests prove the exact package set/version, authenticated
  repository input, no shell discovery, no `apt_key`, no unrelated packages or
  removals, and no configuration/storage/tuning/Manager behavior.
- Ubuntu 24.04 tests pass for the project's supported guest architectures.
- Local package provenance, failure, check-mode, and service-state contract
  tests pass against the upstream mode.
- The upstream pin and local provenance are updated before wrapper-owned
  package logic is removed.

**Official links**

- [Pinned role defaults](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/defaults/main.yml)
- [Pinned Debian package tasks](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/Debian.yml)
- [Pinned version-selection tasks](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/Debian_install.yml)
- [ScyllaDB 2026.2 Linux package installation](https://docs.scylladb.com/manual/branch-2026.2/getting-started/install-scylla/install-on-linux.html)

### SAR-002 configuration-only role mode

**Status:** `Open`

**Affected local feature and files**

- `scylla-configure`
- `scylla_vms/ansible/scylla_configure.py`
- `scylla_vms/ansible/content/playbooks/scylla-configure.yml`
- `scylla_vms/ansible/content/playbooks/roles/scylla_configure/`
- `tests/test_ansible_scylla_configure.py`

**Upstream limitation and evidence**

The pinned role has no path that renders only Scylla configuration. In
[`tasks/main.yml`](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/main.yml),
`install_only=true` ends after OS installation, while
`install_only=false` includes the full
[`tasks/common.yml`](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/common.yml)
before and after rendering the two configuration files.

That common path runs or can run `scylla_setup`, sysconfig/cpuset setup, NVMe
detection, RAID setup, I/O probing, NTP setup, node-exporter setup and startup,
boot-parameter setup, coredump setup, swap setup, CPU-scaling setup, fstrim
setup, Manager Agent configuration, cluster startup/health actions, keyspace
changes, and sysctl changes. Several actions are unconditional within the
common path, so setting selected `skip_*` variables and
`start_scylla_service=false` does not produce an exact configuration-only
contract.

**Local workaround and safety reason**

The local role owns minimal templates for only `scylla.yaml` and
`cassandra-rackdc.properties`. It validates exact package, storage, topology,
seed, address, and provenance inputs; refuses cluster/datacenter/rack relabeling;
writes root-owned mode `0644` files; and performs no package, storage, tuning,
Manager, startup, bootstrap, or health work.

Separating configuration from host tuning, storage preparation, and bootstrap
keeps each mutation under its own evidence and authorization boundary.

**Proposed upstream change**

Add an explicit configuration-only mode or a separately invokable role that:

- accepts a bounded validated configuration model;
- renders only `scylla.yaml` and `cassandra-rackdc.properties`;
- performs no package/repository, setup-script, storage, tuning, sysctl,
  exporter, Manager, service-start, bootstrap, or cluster-health action;
- supports deterministic check mode; and
- exposes file-change and validation results without raw secrets or
  configuration output.

**Acceptance criteria for removing the workaround**

- A new immutable upstream commit provides a documented configuration-only
  entry point whose task graph contains only the intended file and validation
  actions.
- Upstream tests prove that every install, setup, storage, tuning, Manager,
  exporter, service-start, and cluster operation remains absent.
- The mode can represent the project's exact 2026.2 keys, topology, and seed
  policy without patching vendored upstream templates.
- Local idempotence, relabel refusal, file permission/digest, check-mode, and
  provenance tests pass against the upstream entry point.
- Live adoption remains gated until the exact supported baseline is exercised.

**Official links**

- [Pinned role task selection](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/main.yml)
- [Pinned broad common task path](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/common.yml)
- [Pinned upstream `scylla.yaml` template](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/templates/scylla.yaml.j2)
- [Pinned upstream rack/DC template](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/templates/cassandra-rackdc.properties.j2)
- [ScyllaDB 2026.2 configuration and setup sequence](https://docs.scylladb.com/manual/branch-2026.2/getting-started/install-scylla/install-on-linux.html#configure-and-run-scylladb)

### SAR-003 quiescent Scylla service handoff

**Status:** `Open`

**Affected local feature and files**

- `scylla-install`
- `manager-backend-local-install`
- `scylla-configure`
- `scylla-bootstrap`
- `scylla_vms/ansible/content/playbooks/scylla-install.yml`
- `scylla_vms/ansible/content/playbooks/manager-backend-local-install.yml`
- `scylla_vms/ansible/content/playbooks/roles/manager_backend_local_install/`
- `scylla_vms/ansible/content/playbooks/roles/scylla_configure/tasks/main.yml`
- `tests/test_ansible_scylla_install.py`
- `tests/test_ansible_manager_backend_local_install.py`
- `tests/test_ansible_scylla_configure.py`
- `tests/test_ansible_scylla_bootstrap.py`

**Upstream limitation and evidence**

The pinned role's `start_scylla_service` variable defaults to true. Setting it
false skips the final Scylla startup block in
[`tasks/common.yml`](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/common.yml),
but it does not establish a masked-and-inactive service invariant before
package or configuration work.

The pinned Debian installation tasks do not use a package-start suppression
policy, pre-mask `scylla-server`, or verify its final enablement/activity. The
common path also starts node exporter independently of
`start_scylla_service`. Pinned
[`handlers/main.yml`](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/handlers/main.yml)
contains Scylla and related service start/restart handlers, but there is no
single fail-closed option guaranteeing that package installation and
configuration hand off a masked, inactive Scylla service for a separately
authorized bootstrap.

**Local workaround and safety reason**

Local Scylla-node install/configuration and Manager-local-backend package
phases mask and stop `scylla-server` before their work, reassert the state
afterward, and verify `systemctl is-enabled` returns `masked` and
`systemctl is-active` returns `inactive`. Package installation also uses
`policy_rc_d: 101`. The Manager-local adoption does not authorize or start its
one-node backend. Only a separate reviewed bootstrap phase may cross an
unmask/start boundary after revalidating exact authorization and cluster
evidence.

This prevents maintainer scripts, role defaults, or unrelated handlers from
joining a node to a cluster before storage, topology, seed, and recovery
conditions are proven.

**Proposed upstream change**

Add an opt-in quiescent handoff policy that:

- masks and stops `scylla-server` before package or configuration changes;
- suppresses package-script startup;
- blocks Scylla, exporter, and Manager start/restart handlers in that mode;
- verifies and reports final masked/inactive state; and
- requires a separate explicit action to unmask and start Scylla.

**Acceptance criteria for removing the workaround**

- A new immutable upstream commit documents and tests the quiescent policy for
  fresh installation, no-op convergence, package change, and configuration
  change.
- No task or notified handler can start or unmask Scylla, node exporter, or
  Manager while the policy is active.
- A failed package/configuration run preserves or truthfully reports service
  state rather than claiming a safe handoff.
- Local install/configure/bootstrap boundary tests and gated live tests pass
  before the duplicated mask/verify logic is removed.

**Official links**

- [Pinned service defaults](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/defaults/main.yml)
- [Pinned Debian installation tasks](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/Debian.yml)
- [Pinned common configuration/start tasks](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/tasks/common.yml)
- [Pinned service handlers](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/handlers/main.yml)

## Needs upstream verification

### SAR-C001 Ubuntu 24.04 role support declaration

**Status:** `Needs upstream verification`

Pinned
[`meta/main.yml`](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/meta/main.yml)
declares Ubuntu 16.04, 18.04, and 20.04, but not Ubuntu 24.04. Official
ScyllaDB 2026.2 documentation supports 64-bit x86 and AArch64 generally and
directs users to the platform/version support matrix. This is enough to require
verification before adopting the role on the project baseline, but it does not
prove that the role fails on Ubuntu 24.04 or that its maintainers intend the
Galaxy metadata as a complete support matrix.

Do not promote this candidate to `Open` until official role documentation,
upstream CI, a maintainer statement, or a reproducible role failure establishes
the actual support gap. Exact Ubuntu 24.04 and architecture validation remains
project policy meanwhile.

Official references:

- [Pinned role metadata](https://github.com/scylladb/scylla-ansible-roles/blob/42592128ff0399be8ffa18dbc985c4b026e7abd0/ansible-scylla-node/meta/main.yml)
- [ScyllaDB 2026.2 system requirements](https://docs.scylladb.com/manual/branch-2026.2/getting-started/system-requirements.html)
- [ScyllaDB 2026.2 Linux package prerequisites](https://docs.scylladb.com/manual/branch-2026.2/getting-started/install-scylla/install-on-linux.html#prerequisites)

## Examined items that are not upstream-role gaps

- **Exact project baseline and evidence schemas.** Requiring Ubuntu 24.04,
  ScyllaDB 2026.2, OCI/guest architecture parity, strict digests, redacted
  receipts, and stable IDs is this application's compatibility and evidence
  policy. Upstream flexibility is not itself a defect. The unresolved support
  declaration is tracked separately as `SAR-C001`.
- **Storage discovery, preparation, postcheck, and retirement.** This project
  binds provider manifests, stable device identities, wipe authorization, XFS/
  RAID ownership, and recovery boundaries. Those application-specific phases
  are not missing node-role features. Only the inability to avoid upstream
  storage/tuning work during a configuration-only run is part of `SAR-002`.
- **Bootstrap, health, removal, replacement, repair, cleanup, and whole-cluster
  shutdown.** These wrappers implement operation-specific cluster
  orchestration, authorization, health, and no-retry recovery rules. They are
  not replacements for package/configuration responsibilities of the upstream
  node role.
- **Terraform, OCI, inventory, SSH trust, routing, locks, journals, and
  confirmation.** These are application control-plane responsibilities.
- **Manager and monitoring.** The audited repository contains separate Manager
  and monitoring roles, playbooks, and provenance. Those products have their
  own upstream integrations and are not gaps in `scylladb.scylla_node`.
- **Base OS and jump-host hardening.** Generic Ubuntu prerequisites, reboot
  handling, and jump-host SSH policy apply to multiple project roles and are
  intentionally outside the Scylla node role.
- **Vendored signing-key provenance itself.** Full artifact digest, packet,
  subkey, UID, expiry, revocation, and signed-`InRelease` checks are local
  supply-chain requirements. The actionable upstream package-boundary
  shortcomings are recorded in `SAR-001`; the existence of additional local
  provenance is not a separate role gap.
- **Standalone runtime validation.** The local configuration slice truthfully
  reports runtime validation as not performed and delegates runtime health to
  later phases. No role gap is claimed merely because this project refuses to
  start Scylla during configuration.
- **OS upgrade and reprovision refusal contracts.** These are deliberately
  blocked application workflows, not node-role installation/configuration
  shortcomings.

## Maintenance checklist for adopting upstream fixes

When an upstream change may resolve an entry:

- [ ] Review the exact upstream release and immutable commit, including the
      complete task graph, defaults, handlers, templates, dependencies, and
      tests.
- [ ] Confirm the fix covers the entry's acceptance criteria without relying
      on wiki text, mutable branch URLs, or undocumented variable combinations.
- [ ] Recheck Ubuntu 24.04, ScyllaDB 2026.2, `x86_64`, and `aarch64`
      compatibility; do not infer support from syntax alone.
- [ ] Update the pinned role revision and immutable provenance.
- [ ] Add or update unit and contract tests for success, no-op, check-mode,
      failure, interruption, service-state, and forbidden-side-effect paths.
- [ ] Run lint, syntax, idempotence, and disposable integration checks.
- [ ] Keep live host testing separately approved and gated; never remove a
      safety wrapper solely because static source inspection succeeds.
- [ ] Remove or narrow the local workaround only after tests and required live
      gates pass with unchanged authorization, evidence, and recovery
      boundaries.
- [ ] Update this tracker status and evidence, plus `PLAN.md`, `README.md`,
      `AGENTS.md`, and `RELEASE_NOTES.md` when their documented behavior or
      release policy is affected.
