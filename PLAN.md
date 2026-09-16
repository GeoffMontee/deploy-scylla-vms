# Implementation Plan

## Table of contents

- [1. Purpose and status](#1-purpose-and-status)
- [2. Scope](#2-scope)
  - [Initial scope](#initial-scope)
  - [Deliberate non-goals for the first implementation](#deliberate-non-goals-for-the-first-implementation)
- [3. CLI contract and configuration](#3-cli-contract-and-configuration)
  - [Command shape](#command-shape)
  - [Common arguments](#common-arguments)
  - [Resolving node counts per zone](#resolving-node-counts-per-zone)
  - [Scylla datacenter and rack topology](#scylla-datacenter-and-rack-topology)
  - [Configuration precedence](#configuration-precedence)
- [4. Architecture and module layout](#4-architecture-and-module-layout)
  - [Core models and schemas](#core-models-and-schemas)
  - [Stable node identity](#stable-node-identity)
- [5. Terraform responsibilities](#5-terraform-responsibilities)
  - [Storage policy, manifest, and device preparation](#storage-policy-manifest-and-device-preparation)
  - [Per-cluster state and concurrency](#per-cluster-state-and-concurrency)
- [6. Terraform output to Ansible inventory](#6-terraform-output-to-ansible-inventory)
  - [Refresh and conflict handling](#refresh-and-conflict-handling)
- [7. Ansible responsibilities](#7-ansible-responsibilities)
  - [Proposed playbook catalog](#proposed-playbook-catalog)
- [8. SSH, bastions, and host trust](#8-ssh-bastions-and-host-trust)
- [9. Operation workflows](#9-operation-workflows)
  - [Deploy](#deploy)
  - [Add-node](#add-node)
  - [Scale-out](#scale-out)
  - [Replace-node](#replace-node)
  - [Destroy-node](#destroy-node)
  - [Scale-in](#scale-in)
  - [Destroy](#destroy)
  - [Redeploy](#redeploy)
  - [Refresh-monitoring](#refresh-monitoring)
  - [Upgrade-os](#upgrade-os)
  - [Check-jump-hosts](#check-jump-hosts)
- [10. Command execution boundaries](#10-command-execution-boundaries)
- [11. Safety, security, and lifecycle policy](#11-safety-security-and-lifecycle-policy)
- [12. Resumability, idempotency, and drift](#12-resumability-idempotency-and-drift)
- [13. Error handling and exit codes](#13-error-handling-and-exit-codes)
- [14. Test strategy](#14-test-strategy)
  - [Unit tests](#unit-tests)
  - [Contract and integration tests](#contract-and-integration-tests)
  - [End-to-end scenarios](#end-to-end-scenarios)
- [15. Phased milestones and acceptance criteria](#15-phased-milestones-and-acceptance-criteria)
  - [Phase 0 — contracts and scaffold](#phase-0--contracts-and-scaffold)
  - [Phase 1 — safe CLI and state foundation](#phase-1--safe-cli-and-state-foundation)
  - [Phase 2 — OCI Terraform provisioning](#phase-2--oci-terraform-provisioning)
  - [Phase 3 — inventory and baseline Ansible](#phase-3--inventory-and-baseline-ansible)
  - [Phase 4 — deploy and reconciliation](#phase-4--deploy-and-reconciliation)
  - [Phase 5 — node lifecycle and scaling](#phase-5--node-lifecycle-and-scaling)
  - [Phase 6 — maintenance and destruction](#phase-6--maintenance-and-destruction)
  - [Phase 7 — hardening and provider extensibility](#phase-7--hardening-and-provider-extensibility)
- [16. Decisions to resolve before implementation](#16-decisions-to-resolve-before-implementation)
- [17. Authoritative resources to consult](#17-authoritative-resources-to-consult)
  - [Supplied project-specific sources](#supplied-project-specific-sources)
  - [Terraform](#terraform)
  - [Ansible](#ansible)
  - [OCI](#oci)
  - [ScyllaDB operations](#scylladb-operations)
  - [Python and security engineering](#python-and-security-engineering)

## 1. Purpose and status

This document is the implementation plan for a future Python CLI named
`deploy_scylla_vms.py`. It is not an implementation. The tool will provision and
operate ScyllaDB clusters on virtual machines, initially on Oracle Cloud
Infrastructure (OCI), using Terraform for infrastructure and Ansible for host
configuration and orchestration.

The design goals are:

- safe, repeatable cluster lifecycle operations;
- explicit topology and stable node identity;
- secrets that are never accepted as command-line values or stored in generated
  configuration;
- clear separation among CLI policy, cloud provisioning, Terraform state,
  inventory generation, and Ansible orchestration;
- an OCI-first implementation that does not leak OCI-specific models into the
  operation layer; and
- useful dry-run, recovery, drift-detection, audit, and test behavior.

## 2. Scope

### Initial scope

- One Python entry script, with internal modules added as the code grows.
- OCI is the only accepted cloud provider in the first release.
- Terraform manages compute, networking, security controls, storage attachments,
  and related OCI resources for:
  - ScyllaDB nodes;
  - one ScyllaDB Manager host, unless a later explicit topology mode changes this;
  - one monitoring host, distinct from Manager by default; and
  - zero or more jump hosts.
- Ansible installs, configures, validates, and orchestrates ScyllaDB, Manager,
  monitoring, operating-system prerequisites, and rolling lifecycle actions.
- Per-cluster application metadata, Terraform working data/state, generated
  inventory, operation journals, and logs live under an application state
  directory.

### Deliberate non-goals for the first implementation

- AWS or GCP resource implementations.
- A hosted control plane or multi-user API.
- Storing secrets in project files, Terraform variable files, inventory, command
  arguments, or logs.
- Treating Terraform workspaces alone as a cluster isolation boundary.
- Combining Manager and monitoring hosts implicitly. A future opt-in colocated
  mode must document sizing, failure-domain, upgrade, and security tradeoffs.

## 3. CLI contract and configuration

### Command shape

The planned interface is:

```text
python deploy_scylla_vms.py OPERATION [OPTIONS]
```

`OPERATION` is an argparse subcommand backed by an operation registry, not a
single monolithic conditional. The registry will map a name to an operation
handler, required capabilities, mutability class, validation rules, and phases.
This allows new operations to be registered without changing unrelated command
code.

Required initial operations:

| Operation | Planned intent |
| --- | --- |
| `deploy` | Create infrastructure, configure all host roles, and validate a new cluster. |
| `add-node` | Add one explicitly identified Scylla node, bootstrap it, and validate membership. |
| `replace-node` | Replace a failed node while preserving the intended logical identity and following ScyllaDB replacement procedures. |
| `destroy-node` | Safely decommission/remove one explicitly identified node, then remove its infrastructure. |
| `destroy` | Destroy the complete cluster only after inventory/state reconciliation and explicit confirmation. |
| `scale-out` | Increase desired node counts by zone and add nodes through a controlled workflow. |
| `scale-in` | Select and decommission nodes, respecting topology and availability constraints, before reducing infrastructure. |
| `redeploy` | Reconcile or rebuild eligible infrastructure/configuration without silently changing cluster identity. |
| `refresh-monitoring` | Regenerate monitoring targets/configuration and apply/validate the monitoring stack. |
| `upgrade-os` | Apply an approved rolling OS upgrade/reboot workflow with health gates. |
| `check-jump-hosts` | Validate jump-host reachability, SSH forwarding, host identity, and target connectivity without mutation. |

Future operations may include ScyllaDB version upgrades, Manager upgrades,
backup/restore validation, certificate rotation, and explicit drift repair. They
must use the same registry, safety classes, journaling, and phase interfaces.

### Common arguments

- `--cloud-provider oci`: required or defaulted; argparse choices initially
  contain only `oci`. Unsupported providers fail validation before any command is
  run.
- `--cluster-name NAME`: human-readable cluster identifier.
- `--zone ZONE`: repeatable zone/availability-domain argument.
- `--nodes-per-zone ZONE=COUNT`: repeatable, paired mapping.
- `--scylla-datacenter NAME`: optional Scylla logical datacenter name.
- `--scylla-rack ZONE=RACK`: optional repeatable zone-to-Scylla-rack mapping.
- `--jump-host-count COUNT`: integer, default zero.
- `--scylla-instance-type TYPE`
- `--manager-instance-type TYPE`
- `--monitoring-instance-type TYPE`: separate from Manager to avoid the ambiguous
  assumption that one type applies to both.
- `--jump-host-instance-type TYPE`
- `--scylla-storage-backend {auto,local-nvme,block-volume}`: requested data
  backend for newly created Scylla nodes; default `auto`.
- `--scylla-storage-min-device-count COUNT` and
  `--scylla-storage-min-total-gib GIB`: minimum usable non-root device inventory
  required before `auto` or explicit `local-nvme` may select local storage.
- `--scylla-block-volume-count COUNT`,
  `--scylla-block-volume-size-gib GIB`,
  `--scylla-block-volume-vpus-per-gb VPU`, and
  `--scylla-block-volume-attachment-type {iscsi,paravirtualized}`: explicit
  block-volume layout inputs. Provider/version validation may narrow accepted
  combinations.
- `--scylla-block-volume-retention {delete,retain}`: disposition after safe node
  removal/full destroy; default must be chosen and documented before
  implementation rather than inferred during destruction.
- `--state-dir PATH`: absolute or user-expanded application state root. This
  overrides `DEPLOY_SCYLLA_VMS_STATE_DIR`; otherwise the platform-aware default
  described under "Per-cluster state and concurrency" is used.
- `--config PATH`: optional non-secret configuration file in a documented format.
- safety/observability flags such as `--dry-run`, `--plan`, `--yes`,
  `--log-level`, and `--json`.

Operation-specific parsers add selectors, replacement targets, desired counts,
upgrade controls, or approved backup references as needed. Destructive target
selection must use stable node IDs, not only ephemeral IP addresses.

### Resolving node counts per zone

A bare list of zones plus a positional list of counts is error-prone. The
canonical form will be repeated paired mappings:

```text
--zone AD-1 --zone AD-2 \
--nodes-per-zone AD-1=3 --nodes-per-zone AD-2=2
```

Every count key must correspond to exactly one declared zone; duplicate keys,
missing counts, unknown zones, negative counts, and malformed values are errors.
Zero may be allowed only when the operation semantics support removing a zone.
Odd and asymmetric topologies are accepted syntactically, but a topology policy
validator warns or blocks configurations that cannot satisfy the selected
replication/failure-domain objectives. The tool must not invent replication
factors from node count alone.

### Scylla datacenter and rack topology

`scylla_datacenter` and `scylla_rack` are stable, non-secret logical metadata
for each Scylla node. They are distinct from raw provider region/zone display
strings even when they are derived from those values. The desired `ClusterSpec`
and persisted cluster metadata are the source of truth; Terraform receives the
resolved values as inputs and returns them in its host manifest, and Ansible
propagates them without recomputing them.

Users may set one cluster datacenter with `--scylla-datacenter NAME` (or the
equivalent non-secret config field) and map each declared zone with repeated
`--scylla-rack ZONE=RACK` values (or a config mapping). Every declared zone must
resolve to exactly one rack, and every Scylla node in that zone receives that
same rack. Explicit mappings must have no duplicate/unknown zone keys; rack names
must be unique across zones in the initial one-zone-per-rack model.

When values are omitted, the OCI provider adapter supplies deterministic
defaults before cluster metadata is persisted:

- the datacenter is `oci-<normalized-region-key>`; and
- each rack is `rack-<normalized-canonical-zone-key>`.

Normalization produces lowercase ASCII slugs matching
`[a-z][a-z0-9-]*`, collapses/rejects unsupported separators according to one
documented algorithm, enforces a tested maximum length, and fails on an empty
result, reserved name, or collision. OCI availability-domain strings and user
aliases are never copied directly into Scylla rack names. The adapter first
resolves each configured zone to its canonical provider identity, then
normalizes that stable key; if provider identities or truncation normalize to
the same rack, the user must provide unique explicit mappings.

Resolved datacenter/rack values and their source (`explicit` or the named
provider-default algorithm version) are written atomically with initial cluster
metadata. Existing clusters reuse those persisted values rather than recomputing
defaults after provider alias or normalization changes. Any requested change for
an existing Scylla node is a sensitive topology migration, not ordinary config
drift: it can affect replication strategy and data placement and is refused
until a separately designed, version-aware migration validates keyspace
replication, repair/streaming, availability, and rollback implications.

### Configuration precedence

For non-secret settings other than the state root:

1. explicit CLI option;
2. documented environment variable;
3. optional config file value, if config-file support is implemented;
4. built-in default.

Config-file values are defaults below environment variables. The state root has
one narrower, canonical precedence with no config-file input:
`--state-dir` > `DEPLOY_SCYLLA_VMS_STATE_DIR` > platform-aware default. The
implementation must expose the resolved non-secret configuration and absolute
state root in dry-run output.

Examples of non-secret environment defaults:

- `DEPLOY_SCYLLA_VMS_CLOUD_PROVIDER`
- `DEPLOY_SCYLLA_VMS_SCYLLA_INSTANCE_TYPE`
- `DEPLOY_SCYLLA_VMS_MANAGER_INSTANCE_TYPE`
- `DEPLOY_SCYLLA_VMS_MONITORING_INSTANCE_TYPE`
- `DEPLOY_SCYLLA_VMS_JUMP_HOST_INSTANCE_TYPE`
- `DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_BACKEND`
- `DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_MIN_DEVICE_COUNT`
- `DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_MIN_TOTAL_GIB`
- `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_COUNT`
- `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_SIZE_GIB`
- `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_VPUS_PER_GB`
- `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_ATTACHMENT_TYPE`
- `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_RETENTION`

The structured non-secret config model contains one `StoragePolicy` per host
role. CLI/env options initially expose the commonly changed Scylla fields above;
all other policy fields use the same CLI > environment > config file > built-in
default precedence when/if exposed. Scylla defaults to `auto`. Manager and
monitoring default to explicit `block-volume` for their application data, with
separate capacity/performance/retention fields; they never consume local NVMe
implicitly. Jump hosts default to `boot-only`. `local-nvme` is initially invalid
for non-Scylla roles. A config field that has no approved CLI/env spelling must
not be silently overridden through an ad hoc variable.

Secret values are accepted **only from environment variables**. Secret CLI
flags, secret config-file keys, and persistent credential files created by the
tool will not exist. Required secret names are validated without printing
values. OCI authentication must use a supported OCI SDK/provider method that is
compatible with this environment-only secret-input policy; consult the official
auth documentation and define the exact variable contract before implementation.
If an external tool unavoidably requires a file, materialize it from an
environment value as an owner-only, short-lived runtime file and remove it
reliably. Secret values must be redacted from logs, exceptions, displayed
subprocess environments, Terraform plans, inventory, and journals.

## 4. Architecture and module layout

Keep `deploy_scylla_vms.py` as the executable entry point while moving logic into
a package once implementation begins:

```text
deploy_scylla_vms.py          # parser/bootstrap only
scylla_vms/
  cli.py                      # argparse and precedence resolution
  config.py                   # env/config/default resolution and redaction
  models.py                   # validated immutable domain models
  operations/
    base.py                   # operation protocol, phases, safety metadata
    deploy.py
    nodes.py
    destroy.py
    scale.py
    maintenance.py
  providers/
    base.py                   # CloudProvider interface
    oci.py                    # OCI validation and Terraform inputs
  storage.py                  # policy resolution and device/manifest validation
  terraform/
    runner.py                 # init/validate/plan/apply/output/destroy boundary
    state.py                  # paths, locking, snapshots, reconciliation
    templates/                # reviewed Terraform source/modules
  ansible/
    runner.py                 # ansible command boundary
    inventory.py              # Terraform output transformation/validation
    playbooks/
    roles/
  safety.py                   # confirmations, health gates, policy checks
  journal.py                  # resumable operation records
  logging.py                  # structured/redacted logging
  errors.py                   # typed failures and exit-code mapping
tests/
  unit/
  contract/
  integration/
  fixtures/
```

The operation layer depends on abstract provider, Terraform, inventory, and
Ansible interfaces. OCI resource names, OCIDs, shapes, availability domains, and
network rules stay behind the provider/Terraform boundary so an AWS or GCP
implementation can later satisfy the same normalized models.

### Core models and schemas

Use typed, validated models (dataclasses or a deliberately selected validation
library) for:

- `ClusterSpec`: schema version, cluster ID/name, provider, region, zones,
  `scylla_datacenter`, desired role counts, network policy, software
  channels/versions, and role-specific storage policies.
- `ZoneSpec`: normalized zone ID, `scylla_rack`, and desired Scylla node count.
- `HostSpec`: stable logical ID, role, zone, ordinal, provider resource ID,
  private/public addresses, SSH route, lifecycle state, and nullable
  `scylla_datacenter`/`scylla_rack` fields that are required for Scylla hosts,
  plus the persisted storage backend/generation.
- `InstanceTypes`: separate Scylla, Manager, monitoring, and jump-host values.
- `StoragePolicy`: role, requested backend (`auto`, `local-nvme`,
  `block-volume`, or role-restricted `boot-only`), local-device minimums,
  block-volume count/size/performance/attachment/encryption/retention, and
  intended RAID/filesystem/mount-role policy.
- `StorageManifest`: versioned expected provider/guest-device identity,
  selected backend, aggregate capacity, attachment and durability properties,
  and intended initialization/ownership policy for one host.
- `StorageDeviceFact`: read-only OS discovery result containing stable
  by-id/serial/WWN/provider correlation, size, root-disk relationship,
  signatures, partitions, filesystems, mounts, holders, and ownership marker.
- `PreparedStorageRecord`: digest of the approved manifest and discovered
  devices, filesystem/RAID UUIDs, mount roles, logical host/cluster ownership,
  and preparation generation.
- `TerraformOutputs`: versioned output schema containing only expected fields.
- `InventoryModel`: groups, hosts, connection routes, and non-secret variables.
- `OperationRecord`: operation ID, requested target, preconditions, completed
  phases, plan/manifest/prepared-storage digests, wipe/fallback checkpoints,
  timestamps, and non-secret outcomes.

Persist a generated random cluster UUID at initial creation. Validate
`--cluster-name` rather than silently sanitizing it: the initial grammar is
`[a-z][a-z0-9-]{0,62}` with no consecutive/trailing hyphen and an explicit
reserved-name list. The validated value is used unchanged as the directory
component, so different accepted names cannot collapse onto the same path.
Reject separators, dots, traversal, absolute paths, Unicode lookalikes, empty
values, and any resolved cluster root that is not a direct child of
`<state-dir>/clusters/`. Provider resource naming may apply a separately
documented encoding, but cluster UUID tags remain the identity authority.

### Stable node identity

Each node receives a logical ID derived from the cluster UUID, role, zone key,
and a never-reused ordinal or generated node UUID. Provider instance IDs and IP
addresses are attributes, not identity. Removing a node tombstones its logical
ID. Replacement records link old and new provider instances while preserving
the replacement intent required by ScyllaDB. Terraform resources should use
stable `for_each` keys, not list positions, to prevent renumbering cascades.
The selected storage backend and preparation generation are attributes of that
stable identity, not identity themselves. A replacement keeps the logical ID but
does not make old media trustworthy: new local NVMe is rebuilt from surviving
replicas, and a retained block volume may be attached only after its cluster,
logical-host, generation, filesystem, and expected-data disposition are
validated. Stale data is never made safe merely by reusing the logical ID.

## 5. Terraform responsibilities

Terraform will provision and manage, within reviewed modules:

- OCI VCN, subnets, route tables, gateways where required, DNS, and network
  segmentation;
- network security groups/security lists with least-privilege ingress and
  egress;
- compute instances for all host roles;
- boot/block volumes, attachments, and role-appropriate performance settings;
- SSH keys or references to approved key material without embedding private
  keys;
- instance metadata/cloud-init limited to bootstrap needed before Ansible;
- optional reserved/public addresses only where architecture requires them;
- tags/defined tags identifying cluster UUID, role, zone, ownership, and, for
  Scylla nodes, the resolved non-secret datacenter/rack metadata; and
- outputs needed to build inventory and verify resource identity.

The OCI implementation must validate availability-domain/fault-domain and shape
availability through provider-supported data sources or APIs. Network defaults
must not expose database, Manager, monitoring, or SSH ports publicly. Preferred
access is private addressing through zero or more explicitly designed jump
hosts, VPN, or operator network. A zero-jump-host topology is valid only when
the operator has another verified route to private hosts.

Review the [OCI Terraform provider documentation](https://registry.terraform.io/providers/oracle/oci/latest/docs)
before defining resources and data sources; pin compatible provider versions and
commit `.terraform.lock.hcl`.

### Storage policy, manifest, and device preparation

Storage ownership is deliberately split:

- Python resolves policy, validates provider capabilities and manifests,
  controls locks/plans/confirmations/checkpoints, compares guest discovery with
  expected devices, and refuses ambiguity or backend drift.
- Terraform creates block volumes and attachments and emits their non-secret
  provider metadata. It does not format, assemble RAID, mount, or modify guest
  filesystems.
- Ansible discovers guest devices and performs approved guest-side connection,
  destructive preflight, wipe, RAID/filesystem/mount preparation, ownership
  marking, and Scylla storage tuning. It does not create/delete OCI volumes or
  choose the backend.

#### Backend resolution

`StoragePolicy.requested_backend` has these semantics:

- `local-nvme` requires the selected OCI shape to advertise local NVMe and, after
  provisioning, requires an exact unambiguous guest inventory satisfying the
  configured minimum device count and usable aggregate capacity. Any mismatch
  fails without formatting or falling back.
- `block-volume` creates only the declared OCI Block Volumes and excludes every
  local NVMe device from preparation, even if present.
- `auto` consults current OCI shape capabilities before the first Terraform
  plan. It provisionally prefers local NVMe for Scylla only when policy permits
  ephemeral storage and the advertised count/capacity meet the minimums;
  otherwise it selects Block Volume. Shape availability is not storage proof:
  after the instance exists, read-only guest discovery must confirm the actual
  devices. If provisional local NVMe is absent, undersized, or ambiguous,
  Python may checkpoint a fallback and create/attach Block Volumes through a
  second reviewed Terraform plan **only before** any ownership marker,
  filesystem, Scylla data initialization, or cluster join. It then refreshes the
  Terraform manifest and reruns discovery.

OCI local NVMe exists only on shapes that provide it, such as documented Dense
I/O offerings; resolve the exact chosen shape from provider data rather than a
hard-coded family list. Consult [OCI Compute shapes](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm)
and [OCI local NVMe guidance](https://docs.oracle.com/en-us/iaas/Content/Compute/References/nvmedeviceinformation.htm).
Never infer availability from guessed `/dev/nvme*` names.

Once preparation starts, persist the final selected backend, policy digest,
manifest digest, device identities, and preparation generation atomically.
`auto` is no longer reevaluated for that host. A requested/observed backend
change is sensitive runtime drift and requires a separately designed
replacement or data-migration workflow; ordinary deploy/redeploy/upgrade cannot
switch or reinitialize it.

#### Durability and block-volume policy

OCI warns that terminating an instance with local NVMe securely erases those
drives and makes their data unrecoverable; OCI does not back up or protect those
devices. See [Protecting data on NVMe devices](https://docs.oracle.com/en-us/iaas/Content/Compute/References/nvmedeviceinformation.htm)
and [Terminating an instance](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/terminatinginstance.htm).
Therefore local NVMe is ephemeral and a local disk/node is never a backup.
Selection requires an approved replication/failure-domain, free-capacity,
repair/rebuild, replacement-time, and independently verified backup policy.
Node loss/replacement rebuilds from surviving Scylla replicas using the
version-specific replacement procedure; RAID does not replace replication or
backup. If policy requires storage encryption and no reviewed guest-encryption
design compatible with the target Scylla/OS/performance profile exists, reject
local NVMe.

A block-volume policy explicitly declares per role:

- volume count and size, required aggregate/usable capacity, and striping or
  single-volume layout;
- exact VPU-per-GB/performance setting, validated against current service,
  volume-size, attachment, shape, and provider limits rather than hard-coded
  throughput claims;
- `iscsi` or `paravirtualized` attachment, consistent device-path request where
  supported, multipath requirement where applicable, and guest connection
  method;
- OCI-managed or customer-managed at-rest key **identifier**, in-transit
  encryption setting, and whether CHAP is requested. CHAP values are never
  placed in the manifest or process arguments; initial support must refuse CHAP
  unless a reviewed transient secret handoff can satisfy the environment-only
  secret policy without exposing credentials in Terraform output/logs; and
- per-volume delete/retain disposition, backup/snapshot policy, and whether
  retained media may ever be reused.

Validate these choices against the official [Block Volume overview](https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/overview.htm),
[performance/VPU guidance](https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/blockvolumeperformance.htm),
and [attachment guidance](https://docs.oracle.com/en-us/iaas/Content/Block/Tasks/attach-compute-volume-attachment.htm).
Do not assume one attachment or performance tier is universally best.

#### Versioned storage manifest

Each host entry in Terraform output contains a `storage` object with its own
schema version. It is always present: `boot-only` roles use an empty data-device
list. The object contains no secret and includes:

- requested and selected backend, selection algorithm/version and
  provisional/final status, policy digest, and storage generation;
- expected devices in deterministic order, with local/block kind, provider
  volume and attachment OCIDs when applicable, provider-declared local
  slot/device identifiers when available, requested consistent device path,
  expected serial/WWN/by-id identity when the provider exposes one, and expected
  minimum/exact size;
- expected device count, raw and policy-usable aggregate capacity, and whether
  each device is ephemeral;
- attachment type, IQN/portal or multipath metadata only when non-secret,
  in-transit/at-rest encryption mode and customer key identifier, VPU/performance
  setting, and retention/delete behavior; and
- intended RAID level/device, filesystem type/label, stable mount UUID/by-id
  strategy, mount point/options, and data/commitlog/cache/log role allocation.

For local NVMe, fields that OCI does not expose must be explicitly null rather
than fabricated; the manifest still declares expected count/capacity/interface
and the permitted provider-identity predicate. The subsequent
`PreparedStorageRecord` binds actual OS identifiers to this manifest. For Block
Volume, volume/attachment OCIDs and requested device-path metadata are required.
Manifest schema upgrades fail closed on unknown fields or semantics.

#### Guest discovery and destructive preparation

Before any storage mutation, Ansible returns machine-readable `lsblk`/udev,
filesystem-signature, mount, holder, RAID/LVM, and cloud attachment facts.
Python correlates provider volume/attachment metadata, serial/WWN/by-id links,
consistent paths, and instance metadata to an exact OS device set. It traces the
root/boot filesystem through partitions, device mapper, RAID, and holders and
excludes every ancestor/member; it also excludes any device not in the manifest.
Linux enumeration order and wildcard matches are never selectors.

Preflight requires the exact expected count/capacity and one-to-one identity
mapping and inspects partition tables, filesystem/RAID/LVM signatures, mounts,
open holders, swap, and a durable cluster/logical-host/storage-generation
ownership marker. Missing/duplicate serials, multiple possible mappings,
unexpected signatures/data, wrong ownership, or a boot relationship aborts
without change. Reuse requires a separate wipe phase and confirmation naming the
cluster, stable host, provider/device IDs, detected signatures, and retention
impact. Python issues a short-lived operation/checkpoint-bound
`storage_wipe_approved` token; `--yes` cannot bypass mismatch/root protection.
No playbook formats by wildcard or because a disk appears blank by name.

Preparation follows the pinned ScyllaDB/OS version's supported setup, RAID,
filesystem, and I/O tuning flow. Current official guidance describes
`scylla_setup`/`scylla_raid_setup`, XFS, and RAID0 for multiple suitable data
devices, but implementation must validate exact commands and generated
configuration for the selected release; see [ScyllaDB system configuration](https://docs.scylladb.com/manual/stable/getting-started/system-configuration.html)
and [hardware/system requirements](https://docs.scylladb.com/manual/stable/getting-started/system-requirements.html).
RAID0 across local NVMe or Block Volumes is used only when that guidance,
replication policy, and the explicit layout approve it. Create mounts from
filesystem UUID/stable by-id paths with idempotent ownership/options and verify
them after reboot. Data, commitlog, cache, and service-log placement remain
explicit policy choices; never assume one universal split across ScyllaDB,
Manager, monitoring, images, and OS versions.

### Per-cluster state and concurrency

`.gitignore` does not configure state placement. Terraform's `.terraform/`
directory is working data for downloaded providers/modules and backend metadata;
it is not, by itself, the Terraform state directory.

The canonical application state root is resolved exactly as follows:

1. `--state-dir`;
2. `DEPLOY_SCYLLA_VMS_STATE_DIR`; then
3. `platformdirs.user_state_path("deploy-scylla-vms", appauthor=False)`.

Using `platformdirs` is normative so Linux, macOS, Windows, and customized XDG
environments follow the platform's current per-user state convention without
hard-coded home-directory guesses. Expand `~` and environment-provided paths,
make the result absolute, and resolve it safely before adding cluster
components. The one canonical cluster root is:
`<state-dir>/clusters/<validated-cluster-name>/`.

```text
<state-dir>/clusters/<validated-cluster-name>/
  cluster.json
  storage/                      # protected prepared-device/ownership records
  terraform/
    work/                       # staged reviewed .tf and lock-file inputs
    .terraform/                # TF_DATA_DIR provider/module/backend working data
    terraform.tfstate          # initial local-backend state
    terraform.tfstate.backup
    plans/
  ansible/
    inventory.yml
    known_hosts
  operations/
  logs/
  lock
```

The initial canonical backend is local, with its state at the exact path shown
above. A future remote backend may replace the local state file only through an
explicit, tested migration; the per-cluster root remains the location for
working data, plans, inventory, locks, logs, journals, and non-secret backend
metadata. State commonly contains sensitive values even when outputs are marked
sensitive, so it must never be committed, copied into logs, or exposed in
support bundles without sanitization. A remote backend must provide suitable
encryption, access control, versioning, and locking. Terraform workspaces are not
a substitute for this per-cluster isolation or an access-control boundary.

Every Terraform invocation must be anchored to the cluster root, never to the
repository source tree or the caller's current working directory:

- atomically stage a validated copy of reviewed Terraform source and its tracked
  `.terraform.lock.hcl` into `<cluster-root>/terraform/work/`;
- invoke Terraform with
  `-chdir=<cluster-root>/terraform/work` for every subcommand;
- set `TF_DATA_DIR=<cluster-root>/terraform/.terraform`;
- pass an absolute local-backend
  `path=<cluster-root>/terraform/terraform.tfstate` during `terraform init`
  backend configuration, and use explicit absolute state arguments on
  subcommands that require/support them;
- write saved plans only below `<cluster-root>/terraform/plans/`; and
- reject an invocation if the effective working directory, data directory,
  backend state path, or plan path escapes the cluster root.

The implementation must not depend on process `cwd`, Terraform's implicit
default `terraform.tfstate`, or a `.terraform/` directory in the source checkout.
Command construction tests must assert these absolute bindings for `init`,
`validate`, `plan`, `show`, `apply`, `output`, and `destroy`.

Create the state root and cluster directories with owner-only permissions,
subject to platform capabilities. State, plans, inventory, known-hosts, logs,
journals, locks, and temporary credential files use restrictive file modes.
Reject symlinked path components and ownership/permission mismatches. Create
metadata and inventory with write-to-sibling-temporary, flush/fsync where
appropriate, and atomic replace; do not pretend that rewriting Terraform state
outside Terraform is safe.

Acquire an application-level per-cluster file lock before reading or changing
cluster metadata, storage records, Terraform state, generated inventory, or
operation journals.
Include PID/host/operation metadata, bounded waiting, stale-lock diagnostics, and
safe release. Also rely on backend locking where available. Never use
`-lock=false` in normal operation. Detect concurrent plans whose precondition
state serial/lineage or plan digest has changed before apply.

Before creating or initializing new state, detect unexpected state or backend
metadata in the source checkout, the caller's current directory, documented
legacy application paths, and other candidate paths associated with the same
validated cluster name/UUID. If found, stop and report paths without displaying
state contents. Never silently create a second empty state, copy/move state, run
`terraform state` mutations, or delete the unexpected file. A migration workflow
must acquire all relevant locks, verify cluster UUID plus Terraform
lineage/serial, create protected backups, use Terraform-supported backend
migration where applicable, verify the destination, and leave an auditable
journal. Ambiguous or conflicting candidates require operator recovery.

Before a mutating operation:

1. verify the canonical state path, ownership, permissions, and absence of
   conflicting state elsewhere;
2. run Terraform initialization and validation;
3. refresh/reconcile state using an operation-appropriate plan;
4. save a protected state backup or rely on verified backend versioning;
5. produce and review a saved plan;
6. apply exactly that saved plan after confirmation; and
7. capture machine-readable outputs and post-apply state identity.

Never parse human-oriented Terraform output. Consume
`terraform output -json` with a strict schema and explicit handling for
`sensitive`, unknown, null, and missing values. Treat Terraform and its providers
as external binaries with pinned/tested minimum versions.

## 6. Terraform output to Ansible inventory

Terraform outputs will expose a versioned, minimal host manifest: cluster UUID,
logical host IDs, roles, zones, provider IDs, private/public addresses,
jump-host routing references, `scylla_datacenter`, `scylla_rack`, and the
versioned `storage` object defined above. Both
topology fields are required non-empty strings for every Scylla node and are
always present as `null` for Manager, monitoring, and jump hosts so consumers
have one unambiguous schema. They are non-secret logical values, not provider
facts discovered from a VM. The output must echo the values from the persisted
desired topology supplied to Terraform; it must not independently derive them.
The manifest must not expose private keys, tokens, or passwords.

Inventory generation is a deterministic transformation:

1. read JSON output;
2. validate its schema and cluster UUID;
3. normalize/sort hosts by stable logical ID;
4. reject duplicate host IDs, IP conflicts, unknown roles/zones, missing routes,
   provider IDs associated with another logical host, missing/invalid storage
   manifests, backend/policy/storage-generation drift, missing topology fields on
   a Scylla node, non-null topology fields on a non-Scylla host, or a
   datacenter/rack value that differs from the persisted zone mapping;
5. build groups such as `scylla`, `manager`, `monitoring`, `jump_hosts`, and
   zone groups, plus Scylla datacenter/rack groups using inventory-safe derived
   group names;
6. generate `ansible_host`, `ansible_user`, ProxyJump-style connection metadata,
   exact `scylla_datacenter`/`scylla_rack` and validated expected-storage
   hostvars without changing logical values or adding secrets;
7. atomically write an owner-readable generated inventory;
8. run `ansible-inventory --list`/`--graph` validation; and
9. probe identity/reachability when required.

Generated inventory is ephemeral state written only to the external canonical
`<cluster-root>/ansible/` directory. Repository ignore rules remain
defense-in-depth if an inventory is accidentally generated in the checkout; they
do not select its runtime location. An inventory plugin may replace the generated
YAML later, but it must obey the same schema and validation contract.

### Refresh and conflict handling

Refresh and validate inventory from current Terraform state/output:

- after every successful infrastructure apply;
- before every Ansible run if state/output serial or digest changed;
- on explicit reconciliation/monitoring operations; and
- before all sensitive or destructive operations.

Reconciliation compares desired `ClusterSpec`, Terraform state/output, generated
inventory, live provider identity where needed, SSH host keys, and live ScyllaDB
membership including observed datacenter/rack placement. Conflicts are reported
with expected and observed non-secret identifiers. A missing, changed, or
silently renormalized datacenter/rack for an existing node is a sensitive
topology conflict, not an inventory refresh: block sensitive/destructive
operations and do not rewrite cluster metadata, Terraform inputs, inventory, or
live topology labels to make the sources agree. Other stale inventory, duplicate
identity, missing state, unexpected live members/resources, topology drift, or
an unresolved host-key change also blocks the operation. A selected-backend,
device-identity, ownership-marker, policy-digest, or storage-generation mismatch
on an initialized host is likewise sensitive drift; inventory refresh must not
rewrite it or trigger formatting. The tool must never
silently choose Terraform, inventory, or live cluster membership as
authoritative when they disagree.

## 7. Ansible responsibilities

Use reviewed, pinned roles/playbooks and validate compatibility against the
[ScyllaDB Ansible integration guide](https://docs.scylladb.com/manual/stable/using-scylla/integrations/integration-ansible.html),
the [ScyllaDB Ansible roles source](https://github.com/scylladb/scylla-ansible-roles),
and its [wiki](https://github.com/scylladb/scylla-ansible-roles/wiki). The wiki
may be stale; validate instructions against current role source, release tags,
and official ScyllaDB documentation before encoding behavior.

Planned roles/playbooks cover:

- base OS prerequisites, repositories, package pinning, users, time sync,
  kernel/sysctl/limits, boot/system filesystems, and ScyllaDB hardware tuning;
- manifest-bound application-device discovery, preparation, retirement, and
  mount validation;
- ScyllaDB installation and configuration;
- seeds, listen/RPC/broadcast addresses, authentication/encryption policy, and
  the selected snitch/topology properties needed to apply exact persisted
  `scylla_datacenter`/`scylla_rack` values consistently across a node;
- service startup, health checks, and cluster membership validation;
- Manager installation, configuration, cluster registration, repair scheduling,
  and backup task configuration where explicitly requested;
- monitoring stack installation/configuration, target generation, dashboards,
  alerting endpoints, and validation;
- jump-host bootstrap/hardening only where Ansible is the chosen bootstrap
  mechanism;
- add, replace, decommission/remove, rolling restart, configuration update, and
  upgrade orchestration;
- OS patch/upgrade and reboot with one-host-at-a-time health gates; and
- post-operation verification and evidence collection.

### Proposed playbook catalog

All paths below are proposed; no playbook exists yet. Names follow
`ansible/playbooks/<responsibility>.yml`. Python selects the operation sequence,
acquires locks, validates fresh inventory/state, enforces confirmations and
checkpoints, and invokes each playbook with the canonical inventory, an explicit
host limit, and allowlisted non-secret extra variables. Terraform remains solely
responsible for infrastructure. Ansible must not infer provider resources,
select destructive targets, or advance the Python operation journal.

- `ansible/playbooks/inventory-preflight.yml` — controller/read-only validation
  of required groups, stable IDs, role hostvars, datacenter/rack mappings, and
  operation-specific target membership.
- `ansible/playbooks/connectivity-check.yml` — read-only SSH/direct/ProxyJump
  reachability and host-identity checks for the explicitly limited hosts.
- `ansible/playbooks/evidence-collect.yml` — read-only, bounded collection of
  service versions/status, topology, and diagnostics before or after an
  operation; output is returned to Python for redaction and journaling.
- `ansible/playbooks/jump-host-configure.yml` — base configuration and hardening
  for the `jump_hosts` group; it never creates VCN, NSG, route, or compute
  resources.
- `ansible/playbooks/base-os.yml` — idempotent users, repositories, time sync,
  limits, kernel settings, disks/filesystems, and role-specific prerequisites on
  newly provisioned or explicitly reconverged hosts; its baseline phase must not
  discover by wildcard, format, mount, or reinitialize application data devices.
- `ansible/playbooks/storage-discover.yml` — read-only collection of block/NVMe,
  provider identity, root ancestry, signatures, partitions, mounts, holders,
  RAID/LVM, and ownership markers for Python manifest reconciliation.
- `ansible/playbooks/storage-prepare.yml` — after exact manifest validation,
  prepare only the explicitly limited host's approved devices: connect
  attachments where needed, perform separately authorized wipe, assemble the
  declared RAID/filesystem/mounts, write ownership markers, and verify reboot
  persistence. It refuses established backend drift.
- `ansible/playbooks/storage-retire.yml` — after Scylla/service shutdown or
  logical node removal, verify ownership, unmount/deactivate guest storage where
  required, and return retention/deletion evidence; it does not wipe retained
  media or delete/detach OCI resources.
- `ansible/playbooks/scylla-node.yml` — install and configure ScyllaDB on
  `scylla` hosts, including persisted datacenter/rack/snitch topology, but do not
  initiate add/remove/replace topology actions.
- `ansible/playbooks/scylla-health.yml` — read-only ring, membership, schema,
  datacenter/rack, streaming, and service health gates.
- `ansible/playbooks/manager-agent.yml` — install/configure the Manager agent on
  explicitly limited Scylla nodes and verify server-to-agent reachability.
- `ansible/playbooks/monitoring-agent.yml` — install/configure node-side
  monitoring/exporter components without changing monitoring-server targets.
- `ansible/playbooks/manager-server.yml` — install/configure the Manager server,
  register the validated cluster, and verify server health; task creation remains
  explicit.
- `ansible/playbooks/monitoring-stack.yml` — install/configure the monitoring
  server stack, dashboards, alerts, storage/retention, and service validation.
- `ansible/playbooks/monitoring-targets.yml` — atomically refresh target files
  from validated inventory and verify target discovery; it does not install
  ScyllaDB packages.
- `ansible/playbooks/manager-tasks.yml` — inspect, quiesce, resume, or validate
  Manager repair/backup tasks using an explicit `manager_task_action`; default
  action is read-only inspection.
- `ansible/playbooks/scylla-bootstrap.yml` — bootstrap exactly the newly
  provisioned, limited Scylla node(s) under add-node guidance and wait for the
  joining-to-normal transition.
- `ansible/playbooks/scylla-remove-live.yml` — decommission exactly one reachable
  Up Normal Scylla node after Python safety/confirmation gates.
- `ansible/playbooks/scylla-remove-dead.yml` — perform the target-version
  unavailable-node removal for one confirmed permanently down Host ID, including
  repair-based-operation prerequisites/variants.
- `ansible/playbooks/scylla-replace-dead.yml` — configure and bootstrap one new
  host as the replacement for one confirmed dead Host ID, preserving desired
  logical topology and validating streaming.
- `ansible/playbooks/scylla-cleanup.yml` — run post-scale cleanup serially on the
  Python-computed eligible host limit and verify completion before future node
  removal.
- `ansible/playbooks/scylla-repair.yml` — run and verify the
  target-version/Manager-aware repair variant on an explicitly limited node or
  Python-computed serial set when replacement/removal prerequisites require it.
- `ansible/playbooks/service-converge.yml` — idempotently reconcile or restart
  only an explicitly selected service/configuration scope; topology mutation is
  forbidden.
- `ansible/playbooks/scylla-cluster-shutdown.yml` — perform an explicitly
  approved, target-version full-cluster service shutdown before complete
  infrastructure teardown; it is not individual node removal.
- `ansible/playbooks/os-upgrade-preflight.yml` — read-only compatibility,
  package/repository, reboot, capacity, route, and per-host readiness report.
- `ansible/playbooks/os-upgrade-in-place.yml` — apply only an approved in-place
  guest-OS update to one limited host, with role-specific drain/reboot handling;
  unsupported major upgrades are refused.
- `ansible/playbooks/os-reprovision-prepare.yml` — preflight, optional
  target-version drain/quiesce, and evidence for a
  Python/Terraform-controlled immutable host replacement; it never creates or
  destroys the VM.
- `ansible/playbooks/os-upgrade-postcheck.yml` — verify one upgraded/reprovisioned
  host's OS, reboot, service, route, and role-specific cluster health before the
  next host proceeds.

The read-only preflight, connectivity, health, evidence, storage-discovery, and
OS-preflight/postcheck playbooks must support Ansible check mode without
reporting false changes. Configuration playbooks should support
[check/diff mode](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_checkmode.html)
where their modules permit it, but check mode is only a preview. The bootstrap,
remove-live, remove-dead, replace-dead, cleanup, repair, storage-preparation/
retirement, cluster-shutdown, in-place upgrade, and reprovision-preparation
playbooks either mutate topology/host state or coordinate irreversible
boundaries; they must detect and reject check mode rather than simulate safety.
Python provides a separate operation plan.

Use [playbook tags](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_tags.html)
only for documented sub-responsibilities, never to skip required safety gates.
Python supplies explicit inventory patterns/limits following
[Ansible pattern guidance](https://docs.ansible.com/ansible/latest/inventory_guide/intro_patterns.html);
topology-mutating playbooks require one stable host ID unless the catalog entry
explicitly defines a Python-computed serial set. Extra variables are
schema-validated, non-secret operation context such as cluster UUID, stable
target ID, expected datacenter/rack, action variant, and journal checkpoint ID;
secret values remain environment-only.

The exact ScyllaDB configuration files/keys and verification interfaces can vary
by ScyllaDB version and by the pinned upstream role. Playbooks must follow the
version-specific official ScyllaDB guidance rather than hard-coding an assumed
property name. After deploy, add, replace, scale, redeploy, or relevant
maintenance, query supported ScyllaDB operational/system metadata to verify each
stable node reports the desired datacenter/rack. Do not treat an Ansible
"changed" or successful service restart as topology proof. Because these labels
feed replication strategy and data placement, ordinary idempotent convergence
must refuse to relabel an existing node after data exists.

All roles/playbooks must be idempotent: a second run with unchanged inputs should
report no material changes. Handlers, `changed_when`, `failed_when`, check mode,
tags, serial limits, and retries must be deliberate. Pin role/collection
versions. Do not edit vendored upstream role code without a documented patching
policy. For topology-mutating playbooks, idempotence means recognizing the exact
operation/checkpoint and an already-completed postcondition as a no-op; a
different or ambiguous live topology must fail closed rather than repeating the
mutation.

Ansible Vault files or password files are not generated or committed by this
tool. If Vault is added, its password still comes from an environment variable
and never from process arguments.

## 8. SSH, bastions, and host trust

- ScyllaDB, Manager, and monitoring hosts use private addresses by default.
- With jump hosts, assign deterministic target-to-bastion routing, preferably
  zone-local with a documented failover rule. Validate every route before
  configuration.
- With multiple jump hosts, avoid non-deterministic load-balanced SSH identity.
  Record the selected stable jump-host logical ID in inventory.
- With zero jump hosts, require a direct private route and pass connectivity
  checks; do not fall back to public exposure.
- Use argument arrays and generated SSH configuration/Ansible variables rather
  than shell interpolation.
- Maintain a per-cluster known-hosts file. Initial trust must be based on
  provider-derived instance identity or an explicit operator approval. A changed
  key is a conflict, not an invitation to disable host checking.
- Secret private-key material is accepted only through environment variables. If
  a downstream tool needs a path, the process boundary may create an owner-only,
  short-lived file that is never copied into state/inventory and is reliably
  removed.

## 9. Operation workflows

Every operation uses the common phase model: parse/resolve, lock, load metadata,
reconcile, validate preconditions, plan, confirm, execute, verify, journal, and
unlock. Read-only or no-change operations explicitly mark inapplicable phases
instead of pretending to plan/apply or seek unnecessary confirmation. A phase
records durable non-secret completion evidence so an interrupted operation can
safely resume after revalidation.

### Deploy

**Required Ansible playbooks (execution order)**

- **1.** `ansible/playbooks/inventory-preflight.yml`.
- **2.** `ansible/playbooks/connectivity-check.yml`, initially limited to jump
  hosts or directly reachable hosts.
- **3.** If jump hosts exist,
  `ansible/playbooks/base-os.yml` limited to `jump_hosts`, then
  `ansible/playbooks/jump-host-configure.yml`; rerun
  `ansible/playbooks/connectivity-check.yml` for all hosts through final routes.
  With zero jump hosts, require the direct-route connectivity result instead.
- **4.** `ansible/playbooks/base-os.yml` on non-jump managed hosts, then
  `ansible/playbooks/storage-discover.yml`. After Python finalizes each manifest
  (including any pre-initialization `auto` fallback), run
  `ansible/playbooks/storage-prepare.yml` on Scylla, Manager, and monitoring
  hosts, then `ansible/playbooks/scylla-node.yml` on `scylla`.
- **5.** `ansible/playbooks/scylla-health.yml`; do not configure service roles
  until the initial ring/topology gate passes.
- **6.** `ansible/playbooks/manager-server.yml`, then
  `ansible/playbooks/monitoring-stack.yml`.
- **7.** `ansible/playbooks/manager-agent.yml` and
  `ansible/playbooks/monitoring-agent.yml` on healthy Scylla nodes, then
  `ansible/playbooks/monitoring-targets.yml`.
- **8.** `ansible/playbooks/manager-tasks.yml` only for explicitly requested
  registration/task actions, followed by `ansible/playbooks/scylla-health.yml`
  and `ansible/playbooks/evidence-collect.yml`.

1. Resolve configuration, validate the cluster name/topology, and acquire the
   new cluster's state lock; reject an existing cluster identity or unexpected
   Terraform state unless an interrupted deploy journal is safe to resume.
2. Validate environment-supplied credentials, OCI region/zones, node counts,
   explicit/defaulted Scylla datacenter and zone-to-rack mapping, shapes, quotas
   where queryable, role storage policies, local-NVMe count/capacity thresholds,
   Block Volume inputs, SSH route, and least-privilege network intent before
   creating resources. Resolve only a provisional `auto` backend from current
   [OCI shape capabilities](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm);
   not every shape has local NVMe. Validate resource fields against the
   [OCI Terraform provider reference](https://registry.terraform.io/providers/oracle/oci/latest/docs)
   and validate placement/network security against OCI's
   [regions and availability domains](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm),
   [VCN networking](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/overview.htm),
   and [network security groups](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/networksecuritygroups.htm).
3. Atomically create cluster metadata, stable cluster/host identities, desired
   topology including normalization algorithm/version and resolved
   datacenter/rack labels, requested/provisional storage policy and selection
   algorithm, and an operation journal; no Terraform apply occurs until those
   identifiers are durable.
4. Stage Terraform inputs in the canonical cluster root, then run
   [Terraform initialization](https://developer.hashicorp.com/terraform/cli/commands/init),
   validate, and a saved
   [Terraform plan](https://developer.hashicorp.com/terraform/cli/commands/plan);
   use the documented detailed exit codes to distinguish error/no-change/change,
   display the role/zone/resource summary, and require confirmation before apply.
5. Apply exactly the approved plan. On interruption or an uncertain provider
   result, stop at the infrastructure boundary, refresh Terraform state, and
   resume only after the plan/state lineage is reconciled; Terraform documents
   that a failed [apply](https://developer.hashicorp.com/terraform/cli/commands/apply)
   can leave partial changes and does not automatically roll them back.
6. Read fresh Terraform JSON outputs, generate and validate Ansible inventory,
   reject identity/address/zone/datacenter/rack/storage-manifest conflicts, and
   establish SSH host trust and connectivity through the selected direct or
   bastion routes. Run read-only storage discovery and require exact non-root
   device correlation. If provisional `auto` local NVMe fails validation, stop
   before data initialization, checkpoint the fallback, create/attach explicit
   Block Volumes with a second saved Terraform plan, refresh outputs/inventory,
   and repeat discovery; explicit `local-nvme` fails instead. Follow
   the machine-readable
   [`terraform output -json` contract](https://developer.hashicorp.com/terraform/cli/commands/output)
   plus [Terraform's JSON format](https://developer.hashicorp.com/terraform/internals/json-format)
   and the [Ansible inventory guide](https://docs.ansible.com/ansible/latest/inventory_guide/index.html).
7. Finalize/persist each storage manifest, run the separately gated storage
   preparation against exact device IDs, and verify stable mounts/ownership
   before installing/configuring ScyllaDB. Then run idempotent ScyllaDB
   playbooks in topology-safe order, limit initial bootstrap concurrency, and
   wait for all expected nodes to join and converge. Use the
   [ScyllaDB storage setup guidance](https://docs.scylladb.com/manual/stable/getting-started/system-configuration.html),
   [official ScyllaDB Ansible integration](https://docs.scylladb.com/manual/stable/using-scylla/integrations/integration-ansible.html)
   and current [ScyllaDB Ansible roles source](https://github.com/scylladb/scylla-ansible-roles);
   execute through Ansible's documented
   [playbook interface](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_intro.html).
8. Configure the separate Manager and monitoring hosts, register the validated
   cluster, configure only explicitly requested repair/backup tasks, and
   generate monitoring targets from stable identities. Validate the selected
   release against the [ScyllaDB Manager documentation](https://manager.docs.scylladb.com/stable/)
   and [ScyllaDB Monitoring documentation](https://monitoring.docs.scylladb.com/stable/).
9. Validate ScyllaDB membership, datacenter/rack placement, ring health,
   services, Manager registration, monitoring targets, and a no-op convergence
   preview; stop rather than compensate destructively for partial configuration.
   Use the [ScyllaDB administrator procedures index](https://docs.scylladb.com/manual/stable/operating-scylla/)
   for target-version health/status interfaces.
10. Atomically record final desired/observed topology, Terraform state/output
    and plan digests, inventory and storage-manifest/prepared-record digests,
    health evidence, and completed phases. Preserve the journal for safe
    repair/resume if any postcondition failed.

### Add-node

**Required Ansible playbooks (execution order)**

- **1.** `ansible/playbooks/inventory-preflight.yml`,
  `ansible/playbooks/connectivity-check.yml`, and
  `ansible/playbooks/scylla-health.yml` against the existing cluster.
- **2.** `ansible/playbooks/manager-tasks.yml` with read-only inspect action,
  followed by quiesce only when policy requires it.
- **3.** After Terraform creates the host and inventory is refreshed,
  `ansible/playbooks/connectivity-check.yml`,
  `ansible/playbooks/base-os.yml`, and
  `ansible/playbooks/storage-discover.yml`, all limited to the new stable ID.
- **3a.** After Python finalizes the manifest or applies/validates an allowed
  pre-initialization Block Volume fallback, run
  `ansible/playbooks/storage-prepare.yml`, then
  `ansible/playbooks/scylla-node.yml`, limited to the same ID.
- **4.** `ansible/playbooks/scylla-bootstrap.yml` limited to that same ID,
  followed by `ansible/playbooks/scylla-health.yml` on the cluster.
- **5.** `ansible/playbooks/manager-agent.yml` and
  `ansible/playbooks/monitoring-agent.yml` limited to the healthy new node,
  followed by `ansible/playbooks/scylla-cleanup.yml` serially on the computed
  eligible old nodes.
- **6.** `ansible/playbooks/monitoring-targets.yml`,
  `ansible/playbooks/manager-tasks.yml` with validate/resume action, and
  `ansible/playbooks/evidence-collect.yml`.

1. Require exactly one new logical node identity and target zone, resolve its
   persisted cluster datacenter and zone rack plus requested storage policy, and
   reject an existing/tombstoned ID, undeclared/unmapped zone, or request that
   implicitly changes unrelated zone counts, topology labels, or established
   storage backends.
2. Acquire the cluster lock and reconcile cluster metadata, Terraform state,
   fresh Terraform-output inventory, provider identities, and live ScyllaDB
   membership. Stop on drift, stale inventory, or an already-partially-added
   node unless its operation journal gives a valid resume boundary.
3. Verify ring health, failure-domain/replication policy, bootstrap capacity,
   keyspace replication across the resolved datacenter/racks, seed/address
   policy, Manager task posture, and supported ScyllaDB add-node procedure.
   Reserve the requested durable host ID without renumbering existing nodes.
   The [official add-node procedure](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/add-node-to-cluster.html)
   requires existing nodes to be up and warns about rack/RF validity.
4. Produce a saved Terraform plan for only the new host and necessary narrowly
   scoped dependencies; display provider ID/address and provisional/final
   storage-manifest expectations, Block Volume costs/disposition, and local-NVMe
   ephemerality, then require confirmation before applying infrastructure. Model
   the full dependency graph
   and treat the plan command's
   [resource-targeting option](https://developer.hashicorp.com/terraform/cli/commands/plan)
   as exceptional recovery behavior, not the normal way to isolate a node;
   validate the instance/network resources against the
   [OCI provider reference](https://registry.terraform.io/providers/oracle/oci/latest/docs).
5. Apply the plan, refresh Terraform JSON output, regenerate/validate inventory,
   and establish host-key trust and the selected SSH/bastion path for the new
   host. Discover storage read-only; validate exact devices or perform the
   deploy workflow's pre-initialization `auto` fallback/replan before finalizing
   the manifest. Refuse any unrelated resource replacement, following Terraform's
   [saved-plan apply semantics](https://developer.hashicorp.com/terraform/cli/commands/apply)
   and Ansible's [SSH connection guidance](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/ssh_connection.html).
6. Apply base and storage preparation only to the new node, verify its storage
   record and mounts, then configure ScyllaDB and bootstrap it using the
   version-appropriate procedure. Do not add another node concurrently
   unless a future tested policy explicitly permits it; the
   [add-node guide](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/add-node-to-cluster.html)
   requires a matching ScyllaDB patch release and documents bootstrap status.
7. Wait for token streaming/bootstrap completion and healthy membership; if
   configuration fails before join, repair or remove only the new infrastructure
   through a reviewed plan, but after ring mutation journal and resume rather
   than attempting an automatic rollback. Once the node reaches the documented
   healthy state, perform/schedule the guide's required
   [post-add cleanup](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/add-node-to-cluster.html)
   on old nodes, one at a time, and record completion before any later node
   removal.
8. Refresh Manager and monitoring configuration, validate the new node's
   exact datacenter/rack, zone, ownership, service, and scrape/management status,
   then persist the desired count, observed membership/topology,
   inventory/output and storage manifest/prepared-record digests, and operation
   result.

### Scale-out

**Required Ansible playbooks (execution order)**

- **1.** `ansible/playbooks/inventory-preflight.yml`,
  `ansible/playbooks/connectivity-check.yml`,
  `ansible/playbooks/scylla-health.yml`, and read-only
  `ansible/playbooks/manager-tasks.yml`.
- **2.** For each Python-selected node/batch after its Terraform apply:
  `ansible/playbooks/connectivity-check.yml`,
  `ansible/playbooks/base-os.yml`, and
  `ansible/playbooks/storage-discover.yml`, limited to only that batch. After
  manifest finalization/allowed fallback, run
  `ansible/playbooks/storage-prepare.yml` and
  `ansible/playbooks/scylla-node.yml` on that same batch.
- **3.** `ansible/playbooks/scylla-bootstrap.yml` for the batch, then
  `ansible/playbooks/scylla-health.yml` for the full cluster before Python plans
  another batch, followed by `ansible/playbooks/manager-agent.yml` and
  `ansible/playbooks/monitoring-agent.yml` limited to the healthy new nodes.
- **4.** After all additions, `ansible/playbooks/scylla-cleanup.yml` serially on
  the documented Python-computed host set, then
  `ansible/playbooks/monitoring-targets.yml`,
  `ansible/playbooks/manager-tasks.yml` with validate/resume action, and
  `ansible/playbooks/evidence-collect.yml`.

1. Accept a desired per-zone topology, acquire the cluster lock, and calculate
   the expansion from stable current identities; reject decreases (which belong
   to `scale-in`), implicit renumbering, unmapped zones, and any change to
   existing datacenter/rack labels.
2. Reconcile metadata, Terraform state, fresh Terraform-output inventory,
   provider resources, and live membership. Report the exact new IDs/zones and
   stop on drift or an incomplete prior scaling journal.
3. Validate the resulting odd/asymmetric topology, failure-domain/replication
   goals and keyspace replication across the resolved datacenter/racks, quotas,
   network/storage capacity, each new host's storage policy and shape
   capabilities, local-NVMe recovery policy or Block Volume limits, bootstrap
   load, and cluster health. Choose a
   deterministic, topology-safe node addition order under the
   [ScyllaDB out-scale prerequisites](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/add-node-to-cluster.html).
4. Display a complete preview of the expansion and require confirmation for the
   full desired-topology and per-node storage delta, including ephemeral and
   retained/deleted volume outcomes. Partition execution into bounded batches or
   single nodes as required by bootstrap policy; after refreshing state, create
   a separate saved Terraform plan for each batch so no plan is partially
   applied, following Terraform's
   [plan/save workflow](https://developer.hashicorp.com/terraform/cli/commands/plan)
   and the [OCI provider resource contracts](https://registry.terraform.io/providers/oracle/oci/latest/docs).
5. For each approved node/batch, apply exactly its saved infrastructure plan,
   refresh Terraform output and inventory, validate SSH identity/routes, run
   read-only storage discovery, complete any allowed pre-initialization fallback,
   then prepare exact devices before ScyllaDB configuration. Wait for streaming
   plus ring-health gates before planning the next addition. The
   [ScyllaDB add-node procedure](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/add-node-to-cluster.html)
   governs version matching, bootstrap, and Up Normal validation.
6. On failure, stop before the next node, retain the achieved intermediate
   desired/observed distinction, and resume from the journal after
   reconciliation; never destroy a node that has joined the ring as an automatic
   Terraform rollback.
7. After all additions, regenerate Manager/monitoring targets once more and
   validate membership, token ownership, zone/rack distribution, services, and
   the requested final counts. Run/schedule the documented cleanup on all nodes
   required by the target-version procedure, one node at a time; current
   multiple-add guidance says all nodes except the last node added. The
   [official procedure](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/add-node-to-cluster.html)
   states cleanup must finish before a later decommission/removal.
8. Record each completed node boundary, final topology, plan/state/output and
   inventory/storage digests, and health evidence so the expansion is idempotent
   on rerun.

### Replace-node

**Required Ansible playbooks (execution order)**

- **1.** `ansible/playbooks/inventory-preflight.yml`,
  `ansible/playbooks/connectivity-check.yml`,
  `ansible/playbooks/scylla-health.yml`, and
  `ansible/playbooks/evidence-collect.yml` before replacement.
- **2.** `ansible/playbooks/manager-tasks.yml` with inspect/quiesce action as
  required by active tasks and the replacement procedure.
- **3.** After Terraform creates the replacement:
  `ansible/playbooks/connectivity-check.yml`,
  `ansible/playbooks/base-os.yml`, and
  `ansible/playbooks/storage-discover.yml`, limited to the new provider
  generation. After Python rejects stale retained media or finalizes approved
  reuse/new-storage policy, run `ansible/playbooks/storage-prepare.yml` and
  `ansible/playbooks/scylla-node.yml` on that same generation.
- **4.** `ansible/playbooks/scylla-replace-dead.yml` for exactly the confirmed
  dead Host ID, then `ansible/playbooks/scylla-health.yml`, followed by
  `ansible/playbooks/manager-agent.yml` and
  `ansible/playbooks/monitoring-agent.yml` on the healthy replacement.
- **5.** `ansible/playbooks/scylla-repair.yml` only when the target-version
  procedure/RBNO state requires post-replacement repair; if Manager performs the
  repair, its agent/server health must already be validated.
- **6.** `ansible/playbooks/monitoring-targets.yml`,
  `ansible/playbooks/manager-tasks.yml` with validate/resume action,
  `ansible/playbooks/scylla-health.yml`, and
  `ansible/playbooks/evidence-collect.yml`.

1. Require one existing stable logical node ID, the observed failure state, and
   an explicit replacement reason; reject healthy-node replacement without a
   separately approved maintenance policy.
2. Acquire the lock and reconcile metadata, Terraform state, fresh
   Terraform-output inventory, provider identity/address, live membership, and
   the prior node's operation history. Stop if the target is ambiguous, has
   already been replaced, or conflicts with state.
3. Validate surviving-cluster health/capacity, consistency and failure-domain
   policy, repair/backup posture, and the exact replacement procedure supported
   by the target ScyllaDB version. Capture pre-change ring/token and address
   evidence. The [current stable dead-node replacement guide](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/replace-dead-node.html)
   requires topology quorum, a dead target, and matching ScyllaDB version.
4. Preserve the tool's stable logical node identity and record a replacement
   generation, exact datacenter/rack labels, and zone while assigning a new
   provider resource ID. Preserve the established storage backend by default;
   any backend migration requires a separately approved replacement/migration
   design and is never an `auto` fallback. A request to move
   zone/rack/datacenter is not a
   replacement and must be refused as an unsupported topology migration. Do not
   infer replacement identity from an IP address: use the target-version
   procedure's node identifier. Current stable guidance uses the dead node's Host
   ID and explicitly deprecates older address-based parameters; verify this
   against the [version-specific replacement procedure](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/replace-dead-node.html).
   Never manually duplicate tokens or treat this as an ordinary add.
5. Create a saved Terraform replacement plan showing destroyed/created compute,
   storage, addresses, and retained data; state that old local NVMe is erased/
   unrecoverable on termination and the replacement rebuilds from the cluster.
   For retained Block Volumes, require explicit disposition and ownership/
   generation validation and never auto-attach stale media to another logical
   node. Report backup implications and require target-ID plus cluster-ID
   confirmation before apply. Validate compute/image
   fields in the [OCI provider reference](https://registry.terraform.io/providers/oracle/oci/latest/docs)
   and inspect the saved plan with Terraform's
   [plan/apply workflow](https://developer.hashicorp.com/terraform/cli/commands/apply).
6. Apply the infrastructure plan, refresh outputs, regenerate/validate
   inventory, and require explicit approval of the new SSH host key after
   correlating it to the new provider instance. Discover storage and correlate
   actual non-root devices with the new manifest; same logical ID is not
   permission to trust old signatures.
7. Prepare only validated new/approved retained storage, verify mounts and
   ownership, then configure the replacement host and invoke the supported
   replacement bootstrap. Wait for streaming, token ownership, schema, and
   ring-health gates;
   do not run another topology operation concurrently. Perform post-replacement
   repair when required by the
   [replacement guide](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/replace-dead-node.html);
   account for target-version repair-based node operations before deciding it
   can be omitted.
8. Once replacement has entered the ring, automatic rollback is prohibited.
   Journal the last verified phase and resume after reconciliation; failed
   pre-join infrastructure may be replanned only if the old-node evidence and
   replacement generation remain intact.
9. Refresh Manager and monitoring, verify the old provider instance is absent or
   explicitly retained for forensics, validate the stable-ID-to-new-generation
   mapping, selected backend, new prepared-storage record, and cluster health,
   and record before/after topology and digests.

### Destroy-node

**Required Ansible playbooks (execution order)**

- **1.** `ansible/playbooks/inventory-preflight.yml`,
  `ansible/playbooks/connectivity-check.yml`,
  `ansible/playbooks/scylla-health.yml`, and
  `ansible/playbooks/evidence-collect.yml`.
- **2.** `ansible/playbooks/manager-tasks.yml` with inspect/quiesce action.
- **3a — live node.** `ansible/playbooks/scylla-remove-live.yml`, limited to the
  confirmed reachable Up Normal stable ID.
- **3b — permanently dead node.** If required before removal,
  `ansible/playbooks/scylla-repair.yml` on the Python-computed surviving set,
  then `ansible/playbooks/scylla-remove-dead.yml` with the confirmed dead Host
  ID. Never run both live and dead removal variants.
- **4.** `ansible/playbooks/scylla-health.yml` must pass before Python permits
  storage retirement and Terraform deletion. If the target remains reachable,
  run `ansible/playbooks/storage-retire.yml` with the confirmed ephemeral/
  delete/retain disposition. For a permanently dead target, skip that playbook
  and require Python to reconcile the protected prepared-storage record with
  provider attachment state before deletion.
- **5.** After Terraform deletion and fresh inventory:
  `ansible/playbooks/monitoring-targets.yml`,
  `ansible/playbooks/manager-tasks.yml` with validate/resume action,
  `ansible/playbooks/scylla-health.yml`, and
  `ansible/playbooks/evidence-collect.yml` on surviving hosts.

1. Require exactly one existing stable node ID and whether it is a healthy
   decommission or failed-node removal; full-cluster teardown belongs to
   `destroy`, and topology-based contraction belongs to `scale-in`.
2. Acquire the cluster lock and reconcile metadata, Terraform state, fresh
   Terraform-output inventory, provider resources, and live ScyllaDB membership.
   Refuse ambiguous identity, stale inventory, unexpected members, or a prior
   incomplete node operation without a valid resume path.
3. Verify cluster/ring health, post-removal replication and failure-domain
   safety by datacenter/rack, remaining capacity, keyspace replication,
   repair/backup and Manager-task posture, and the version-specific decommission
   or failed-node removal procedure. Also require any prior scale-out cleanup to
   be complete. The [official remove-node guide](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/remove-node.html)
   documents disk-capacity/RF-rack checks and distinguishes a live decommission
   from unavailable-node removal.
4. Present the exact node/provider IDs, data/storage disposition, resulting
   topology, local-NVMe irreversible loss, and per-Block-Volume retain/delete
   outcome in the ordered Scylla-then-storage-retirement-then-Terraform plan;
   require destructive confirmation before changing ring membership.
5. Disable or coordinate relevant Manager/monitoring activity, then decommission
   a live Up Normal node, or use the supported unavailable-node removal only
   after recovery is exhausted. Wait until membership and token ownership prove
   the target is safely removed. Current
   [ScyllaDB removal guidance](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/remove-node.html)
   recommends decommission for a running node and reserves `removenode` for a
   permanently down node, with repair prerequisites unless the target version's
   repair-based operation changes them.
6. Treat successful ring removal as an irreversible resume boundary: record it
   before infrastructure deletion and never try to re-add the old VM
   automatically if later Terraform work fails.
7. Refresh Terraform state, create and confirm a saved plan that removes only
   the target VM/volumes/attachments and approved dependencies, apply it, then
   regenerate inventory from fresh outputs. Before apply, run storage retirement
   to verify the ownership/disposition record; retained Block Volumes stay
   tagged/bound to the tombstoned logical identity and are not wiped or
   reassigned. Logical removal must already be proven; use the
   [Terraform plan reference](https://developer.hashicorp.com/terraform/cli/commands/plan)
   to review graph effects and do not use targeted destroy as a substitute for
   ScyllaDB decommission/removal. Confirm OCI instance, VNIC, and volume effects
   against the [OCI provider reference](https://registry.terraform.io/providers/oracle/oci/latest/docs).
8. Tombstone the logical ID, refresh Manager/monitoring, validate surviving
   ring/services/topology and absence of the provider resource, and record
   membership evidence, storage disposition/retained-volume ownership, and
   state/output/inventory digests.

### Scale-in

**Required Ansible playbooks (execution order)**

- **1.** `ansible/playbooks/inventory-preflight.yml`,
  `ansible/playbooks/connectivity-check.yml`,
  `ansible/playbooks/scylla-health.yml`, read-only
  `ansible/playbooks/manager-tasks.yml`, and
  `ansible/playbooks/evidence-collect.yml`.
- **2.** For each Python-selected candidate, use the `destroy-node` variant:
  `ansible/playbooks/scylla-remove-live.yml`, or, only for a confirmed
  permanently dead node, conditional `ansible/playbooks/scylla-repair.yml`
  followed by `ansible/playbooks/scylla-remove-dead.yml`.
- **3.** Run `ansible/playbooks/scylla-health.yml` after each logical removal
  and, when the target is reachable, then
  `ansible/playbooks/storage-retire.yml` for the confirmed storage disposition
  before its Terraform deletion or selection of the next candidate. For a dead
  target, use the `destroy-node` protected-record/provider reconciliation path.
- **4.** After each refreshed inventory, and finally after the contraction:
  `ansible/playbooks/monitoring-targets.yml`,
  `ansible/playbooks/manager-tasks.yml` with validate/resume action,
  `ansible/playbooks/scylla-health.yml`, and
  `ansible/playbooks/evidence-collect.yml`.

1. Accept lower desired per-zone counts, acquire the lock, and reject increases
   (which belong to `scale-out`) or mixed deltas that obscure the contraction.
2. Reconcile metadata, Terraform state, fresh Terraform-output inventory,
   provider resources, and live membership; calculate deterministic candidates
   by stable ID, never by list index or ephemeral address.
3. Validate the final odd/asymmetric topology, replication/failure-domain
   policy by datacenter/rack, keyspace replication, capacity, ring health,
   backup/repair posture, and Manager tasks. Refuse counts that would remove the
   last required role/zone/rack capacity or begin before required post-add
   cleanup is complete. Apply the
   [ScyllaDB down-scale capacity and rack checks](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/remove-node.html)
   to each candidate.
4. Display every selected stable/provider ID, zone order, data/storage outcome,
   local-NVMe loss, Block Volume retain/delete outcome, and final topology; allow
   explicit candidate override only after revalidation, then require
   confirmation for the complete contraction.
5. Process one node at a time by invoking the `destroy-node` safety sequence:
   decommission/remove in Scylla first, durably record that ring boundary, then
   apply the narrowly scoped Terraform deletion and refresh inventory. Follow
   the [official live/dead removal distinction](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/remove-node.html);
   Terraform VM deletion never substitutes for logical ring removal, and OCI
   dependencies must match the [OCI provider plan](https://registry.terraform.io/providers/oracle/oci/latest/docs).
6. Stop on any failed health or capacity gate. Preserve the safely achieved
   intermediate topology and resume from the next journaled candidate after
   reconciliation; never continue deleting to force the requested count.
7. After the final removal, refresh Manager and monitoring and validate surviving
   membership, token ownership, zone/rack distribution, services, and desired
   counts.
8. Persist tombstones, per-node completion evidence, final desired/observed
   topology, storage dispositions, Terraform and inventory digests, and any
   partial-result status.

### Destroy

**Required Ansible playbooks (execution order)**

- **1.** Before the destroy plan/confirmation:
  `ansible/playbooks/inventory-preflight.yml`,
  `ansible/playbooks/connectivity-check.yml`,
  `ansible/playbooks/scylla-health.yml`,
  `ansible/playbooks/manager-tasks.yml` with inspect action, and
  `ansible/playbooks/evidence-collect.yml`.
- **2.** After confirmation, `ansible/playbooks/manager-tasks.yml` with quiesce
  action.
- **3.** Normally, `ansible/playbooks/scylla-cluster-shutdown.yml` performs the
  approved full-cluster service shutdown. If the target-version teardown runbook
  explicitly requires logical node removal, use
  `ansible/playbooks/scylla-remove-live.yml` or the conditional
  `ansible/playbooks/scylla-repair.yml` plus
  `ansible/playbooks/scylla-remove-dead.yml` one confirmed node at a time, with
  `ansible/playbooks/scylla-health.yml` between nodes.
- **4.** Run `ansible/playbooks/evidence-collect.yml` for final reachable-host
  evidence, then `ansible/playbooks/storage-retire.yml` with the reviewed
  per-volume disposition before Terraform apply. No Ansible playbook may run
  after Terraform destroys the hosts; Python/provider/state verification
  completes teardown.

1. Require the full-cluster operation explicitly; reject node selectors and
   direct callers to `destroy-node`/`scale-in` for individual membership changes.
2. Acquire the exclusive cluster lock and reconcile metadata, Terraform state,
   fresh Terraform-output inventory, provider resources, and live membership.
   Refuse missing/ambiguous state, unmanaged members, or unresolved partial
   operations unless a separately designed recovery workflow resolves them.
3. Capture a protected pre-destroy diagnostic snapshot of topology, Terraform
   outputs, inventory, health, Manager tasks, monitoring targets, and resource
   IDs, storage manifests, ownership records, and per-volume dispositions.
   Report independently verified backup status and all retained/external
   resources; local NVMe will be unrecoverable after termination and neither it
   nor a Terraform snapshot is implicitly a database backup.
   Consult the [ScyllaDB administrator procedures index](https://docs.scylladb.com/manual/stable/operating-scylla/)
   for version-specific shutdown/backup requirements.
4. Plan the application-level shutdown order and create a saved Terraform
   destroy plan. Display the validated cluster name and UUID, complete resource
   inventory, every ephemeral data loss and Block Volume retain/delete action,
   network/shared-resource effects, and diagnostic retention policy. Create it
   with the documented
   [`terraform plan -destroy` mode](https://developer.hashicorp.com/terraform/cli/commands/plan)
   and an explicit output path; do not rely on an unsaved speculative plan.
   Reconcile the resource set with the
   [OCI provider reference](https://registry.terraform.io/providers/oracle/oci/latest/docs).
5. Require strong confirmation that includes the exact cluster name and UUID;
   noninteractive approval also requires the dedicated destructive opt-in and
   cannot bypass identity, drift, backup-policy, or plan checks.
6. Quiesce/disable Manager tasks and monitoring writes as designed, then perform
   any required final ScyllaDB service shutdown and storage retirement/
   disposition verification while hosts remain reachable. Do not individually decommission
   every node unless the supported full-cluster procedure specifically requires
   it.
7. Apply exactly the reviewed saved destroy plan with
   [`terraform apply PLAN_FILE`](https://developer.hashicorp.com/terraform/cli/commands/apply).
   Do not switch to `terraform destroy` after approval because that convenience
   command creates a new plan and does not accept the reviewed plan file, as
   documented in the [destroy command reference](https://developer.hashicorp.com/terraform/cli/commands/destroy).
   If interrupted or the provider outcome is uncertain, retain state and
   journal, refresh/reconcile, and produce a new destroy plan; do not delete
   state to make Terraform forget residual resources. Terraform infrastructure
   deprovisioning does not make live ScyllaDB ring removal safe.
8. Verify through Terraform state and provider queries that all planned
   resources are gone and report approved retained/shared resources. Terraform
   outputs/inventory may no longer be available after destruction, so use the
   protected pre-destroy snapshot for diagnostics rather than regenerating a
   fictitious live inventory. Handle state as sensitive data under
   [Terraform state guidance](https://developer.hashicorp.com/terraform/language/state).
9. Mark the cluster destroyed and retain the converged Terraform state,
   sanitized diagnostics, tombstone, plan digest, retained-volume ownership/
   disposition records, and operation journal under the canonical cluster root.
   Remove only ephemeral credentials/generated connection data according to
   retention policy; never silently erase lifecycle evidence.

### Redeploy

**Required Ansible playbooks (execution order)**

- **1.** For every scope: `ansible/playbooks/inventory-preflight.yml`,
  `ansible/playbooks/connectivity-check.yml`, conditional
  `ansible/playbooks/scylla-health.yml` when Scylla is in scope, and
  `ansible/playbooks/storage-discover.yml` plus
  `ansible/playbooks/evidence-collect.yml`. Established storage is validation
  only and must never invoke `ansible/playbooks/storage-prepare.yml`.
- **2 — service scope.** `ansible/playbooks/service-converge.yml` with one
  allowlisted service/tag set and explicit host limit.
- **2 — host scope.** After any approved Terraform replacement,
  `ansible/playbooks/connectivity-check.yml` then
  `ansible/playbooks/base-os.yml` and
  `ansible/playbooks/storage-discover.yml`; a newly replaced stateless service
  host runs `ansible/playbooks/storage-prepare.yml` only after Python validates
  its new/retained manifest, followed by the host role playbook:
  `ansible/playbooks/jump-host-configure.yml`,
  `ansible/playbooks/manager-server.yml`,
  `ansible/playbooks/monitoring-stack.yml`, or the Scylla `replace-node`
  sequence; optionally apply `ansible/playbooks/manager-agent.yml` and
  `ansible/playbooks/monitoring-agent.yml` on Scylla hosts.
- **2 — cluster scope.** `ansible/playbooks/base-os.yml`,
  `ansible/playbooks/storage-discover.yml`,
  `ansible/playbooks/scylla-node.yml`,
  `ansible/playbooks/manager-server.yml`,
  `ansible/playbooks/monitoring-stack.yml`, and
  `ansible/playbooks/manager-agent.yml`,
  `ansible/playbooks/monitoring-agent.yml`, then
  `ansible/playbooks/monitoring-targets.yml`, each limited to its role and
  omitting any no-change/out-of-scope playbook. It never runs storage
  preparation for established hosts.
- **3.** `ansible/playbooks/scylla-health.yml` where applicable, then
  `ansible/playbooks/evidence-collect.yml`. Topology mutation playbooks are
  forbidden except through the delegated add/remove/replace workflow.

1. Require an explicit scope and target: `service` for selected configuration/
   service convergence, `host` for one stable host, or `cluster` for
   cluster-wide reconciliation. Reject an unscoped request.
2. Acquire the lock and reconcile metadata, Terraform state, fresh
   Terraform-output inventory, provider identities, live membership, and the
   selected scope. Run storage discovery for affected hosts and stop on
   topology/identity/storage drift, including any existing datacenter/rack,
   backend, device, ownership, or generation mismatch, instead of interpreting
   it as permission to recreate resources, relabel nodes, or initialize disks.
3. Produce a scope-specific preview: Ansible-only service convergence,
   Terraform no-op/reconciliation plus Ansible for infrastructure configuration,
   or an explicitly identified host reprovision. By default, `redeploy` means
   reapply/reconcile, not destroy and recreate; established storage is validated
   but never reformatted. Use
   [Ansible check/diff mode](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_checkmode.html)
   only as a preview with documented limitations and use
   [Terraform plan](https://developer.hashicorp.com/terraform/cli/commands/plan)
   for infrastructure scope.
4. For service scope, validate capacity and dependencies, confirm any restart,
   run the smallest idempotent playbook/tag set, and health-check before moving
   to another service or host.
5. For host scope, permit ordinary reprovision only for stateless/approved
   roles. Reprovisioning a ScyllaDB node must delegate to `replace-node`; deleting
   it through a Terraform replacement plan is forbidden. Jump-host, Manager, and
   monitoring replacements require role-specific reachability/availability
   plans and confirmation. OCI image-based replacement must follow the
   [OCI Compute image documentation](https://docs.oracle.com/en-us/iaas/Content/Compute/References/images.htm)
   and the [OCI provider's reviewed replacement plan](https://registry.terraform.io/providers/oracle/oci/latest/docs).
6. For cluster scope, apply only a reviewed Terraform plan and bounded Ansible
   convergence that preserve cluster UUID, stable node IDs, and state. Any
   resource replacement is highlighted and separately confirmed under
   Terraform's [saved-plan apply semantics](https://developer.hashicorp.com/terraform/cli/commands/apply)
   and the [ScyllaDB Ansible integration](https://docs.scylladb.com/manual/stable/using-scylla/integrations/integration-ansible.html).
7. Journal each host/service boundary. On failure, stop further convergence,
   preserve already healthy changes, and resume only after fresh reconciliation;
   rollback is limited to an explicitly tested configuration rollback, never an
   inferred infrastructure destroy.
8. Refresh outputs/inventory when infrastructure changed, then validate ring,
   services, storage identity/mounts, SSH routes, Manager, and monitoring for
   the requested scope and record plan/config/inventory/storage digests plus
   observed health.

### Refresh-monitoring

**Required Ansible playbooks (execution order)**

- **1.** `ansible/playbooks/inventory-preflight.yml`,
  `ansible/playbooks/connectivity-check.yml` limited to monitoring/Manager and
  representative targets, then `ansible/playbooks/scylla-health.yml`.
- **2.** `ansible/playbooks/monitoring-targets.yml`.
- **3.** `ansible/playbooks/monitoring-stack.yml` only when server-side
  monitoring configuration/validation requires convergence; use
  `ansible/playbooks/manager-server.yml` only for explicitly requested Manager
  monitoring integration.
- **4.** `ansible/playbooks/evidence-collect.yml`. Normally do not run
  `ansible/playbooks/scylla-node.yml`,
  `ansible/playbooks/manager-agent.yml`, or
  `ansible/playbooks/monitoring-agent.yml`; agent/package drift belongs to an
  explicit `redeploy` scope.

1. Acquire the cluster lock, read current Terraform state/output without an
   infrastructure apply, regenerate/validate inventory, and compare stable host
   identities with live ScyllaDB membership using the
   [`terraform output -json` interface](https://developer.hashicorp.com/terraform/cli/commands/output)
   and [Ansible inventory model](https://docs.ansible.com/ansible/latest/inventory_guide/index.html).
2. Stop on duplicate/stale identities, unexpected live members, unreachable
   monitoring hosts, or topology drift; monitoring refresh must not conceal a
   cluster/state conflict.
3. Derive a deterministic target/configuration diff for ScyllaDB, Manager, and
   monitoring components, preserving exact datacenter/rack labels, zones,
   endpoints, dashboards, alerts, retention, and non-secret operator settings.
4. Preview the generated targets and Ansible monitoring-only changes. Require
   confirmation for monitoring service restarts or destructive retention/data
   changes, but do not create a Terraform apply merely to rewrite targets.
   Treat [Ansible check/diff mode](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_checkmode.html)
   as an estimate, not proof of convergence.
5. Atomically write the external generated inventory/target inputs and run only
   the monitoring role/playbook against monitoring hosts; do not mutate
   ScyllaDB membership, packages, or unrelated cluster infrastructure. Follow
   the target release's [ScyllaDB Monitoring documentation](https://monitoring.docs.scylladb.com/stable/)
   and [Manager documentation](https://manager.docs.scylladb.com/stable/) for
   their respective targets/agents.
6. Validate configuration syntax, service health, target discovery/scrape
   status, expected node/Manager coverage, and absence of stale targets. Restore
   the prior generated monitoring configuration only when that rollback is
   explicitly supported and validated.
7. Record inventory/output and target/config digests, monitoring health
   evidence, changes/restarts, and a resumable failure boundary; leave the
   Terraform state unchanged.

### Upgrade-os

**Required Ansible playbooks (execution order)**

- **1.** `ansible/playbooks/inventory-preflight.yml`,
  `ansible/playbooks/connectivity-check.yml`,
  `ansible/playbooks/scylla-health.yml` where applicable,
  `ansible/playbooks/storage-discover.yml`,
  `ansible/playbooks/manager-tasks.yml` with inspect/quiesce action, and
  `ansible/playbooks/evidence-collect.yml`.
- **2.** `ansible/playbooks/os-upgrade-preflight.yml` serially for every scoped
  host before mutation.
- **3a — supported in-place path.**
  `ansible/playbooks/os-upgrade-in-place.yml` for exactly one host.
- **3b — immutable reprovision path.**
  `ansible/playbooks/os-reprovision-prepare.yml`, then Python checkpoints and
  Terraform replaces the host. After fresh inventory, run
  `ansible/playbooks/connectivity-check.yml`,
  `ansible/playbooks/base-os.yml`,
  `ansible/playbooks/storage-discover.yml`, and, only for a new/approved
  retained non-Scylla data device, `ansible/playbooks/storage-prepare.yml`, then
  exactly the role path:
  `ansible/playbooks/jump-host-configure.yml` for a jump host,
  `ansible/playbooks/manager-server.yml` for Manager, or
  `ansible/playbooks/monitoring-stack.yml` for monitoring. A Scylla host must
  delegate to the `replace-node` sequence, including
  `ansible/playbooks/storage-prepare.yml`,
  `ansible/playbooks/scylla-node.yml`,
  `ansible/playbooks/scylla-replace-dead.yml`,
  `ansible/playbooks/manager-agent.yml`, and
  `ansible/playbooks/monitoring-agent.yml`, rather than generic reprovision.
- **4.** `ansible/playbooks/os-upgrade-postcheck.yml`, then
  `ansible/playbooks/scylla-health.yml` where applicable, before Python advances
  to another host. Never run both in-place and reprovision variants for one host.
- **5.** After all hosts, `ansible/playbooks/manager-tasks.yml` with
  validate/resume action and `ansible/playbooks/evidence-collect.yml`.

1. Require an approved source/target OS and repository policy, explicit role/
   host scope, maintenance window, and evidence that the OS change is compatible
   with installed ScyllaDB, Manager, monitoring, Ansible, and OCI tooling. Do not
   combine a ScyllaDB major-version upgrade with this operation. The
   [ScyllaDB upgrade index](https://docs.scylladb.com/manual/stable/upgrade/)
   governs ScyllaDB product/package paths but does not by itself authorize an
   arbitrary guest-OS major upgrade.
2. Acquire the lock and reconcile metadata, Terraform state, fresh
   Terraform-output inventory, provider image metadata, storage manifests/
   prepared records, live membership, and any prior upgrade journal. Run
   read-only device discovery and stop on drift or uncertain host/storage
   generation.
3. Validate backups, ring/schema health, streaming/repair activity, free
   capacity, failure-domain tolerance, jump-host path redundancy, and
   Manager/monitoring availability. Refuse to begin if loss of one scoped host
   would violate policy.
4. Generate a per-host preflight/package/reboot plan and deterministic order.
   Call out that in-place package upgrade versus provider-image reprovision has
   different Terraform and data implications, especially unrecoverable local
   NVMe and retained Block Volume ownership. Until later design approves image
   reprovision, it is not an implicit part of `upgrade-os`, and Scylla host
   reprovision must use replacement semantics. Consult the
   [OCI Compute image lifecycle documentation](https://docs.oracle.com/en-us/iaas/Content/Compute/References/images.htm)
   and [ScyllaDB dead-node replacement procedure](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/replace-dead-node.html)
   before selecting replacement over an explicitly supported in-place path.
5. Display package removals, reboot needs, role order, capacity impact, and any
   Terraform image change; require confirmation before the first mutation and
   separate replacement confirmation if a future provider-image path is used.
6. Process exactly one host at a time. For a Scylla node, drain/coordinate only
   as required by version-specific guidance, apply the OS role, reboot if
   needed, verify the established storage devices/RAID/mounts without running
   preparation or wipe, restore service, and wait for membership, schema, token,
   and application health before continuing. Use the
   [ScyllaDB administrator procedures](https://docs.scylladb.com/manual/stable/operating-scylla/)
   and pinned [Ansible roles source](https://github.com/scylladb/scylla-ansible-roles)
   for the target release rather than promising a universal package sequence.
7. Upgrade jump hosts only while another validated route or an approved
   maintenance outage exists; upgrade Manager/monitoring hosts under their
   role-specific task, data, and observability safeguards.
8. Journal before patch, before reboot, and after health validation. On failure,
   stop the rollout; resume the same host after reconciliation. Package rollback
   or image rollback occurs only when explicitly supported/tested and must not
   create a second Scylla identity or stale address.
9. After all hosts, refresh Terraform output/inventory if provider attributes
   changed, rerun cluster/SSH/Manager/monitoring health checks, verify OS
   versions, established storage identities/mounts, and no pending reboot, and
   record each host result plus final topology and digests.

### Check-jump-hosts

**Required Ansible playbooks (execution order)**

- **1.** `ansible/playbooks/inventory-preflight.yml` in read-only/check mode.
- **2.** `ansible/playbooks/connectivity-check.yml`, limited to `jump_hosts` and
  their assigned target paths. No configuration, topology, OS, service, or
  evidence-collection playbook is permitted.

1. Run read-only by default, acquiring a shared/read cluster lock where
   supported (otherwise the normal lock), and reject flags that imply Terraform
   apply, host-key replacement, security-rule edits, or host mutation.
2. Reconcile cluster metadata with current Terraform state and fresh JSON
   outputs, derive and validate inventory in memory or a temporary protected
   file without replacing canonical inventory, and stop on jump-host identity,
   address, zone, or host-key conflicts. Use the machine-readable
   [Terraform output contract](https://developer.hashicorp.com/terraform/cli/commands/output)
   and [Ansible inventory guide](https://docs.ansible.com/ansible/latest/inventory_guide/index.html).
3. Validate each configured direct or ProxyJump route: operator-to-bastion,
   bastion-to-assigned-private-host, deterministic multi-bastion selection, and
   zero-jump-host direct routing where applicable. Compare the design with
   [OCI Bastion concepts and session types](https://docs.oracle.com/en-us/iaas/Content/Bastion/Concepts/bastionoverview.htm)
   and OpenSSH's [`ProxyJump` configuration](https://man.openbsd.org/ssh_config).
4. Correlate OCI provider IDs/addresses with the per-cluster known-hosts data,
   then test DNS/address resolution, SSH authentication, forwarding policy, and
   bounded noninteractive connectivity without disabling host-key checking.
5. Probe representative or all assigned ScyllaDB, Manager, and monitoring
   targets according to the requested depth; distinguish network/security-list,
   bastion SSH, target SSH, authentication, and host-key failures without
   exposing credentials. Diagnose paths against
   [OCI VCN networking](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/overview.htm),
   [OCI network security groups](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/networksecuritygroups.htm),
   and the [Ansible SSH connection reference](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/ssh_connection.html).
6. Make no Terraform, Ansible, firewall, package, service, inventory, or
   known-hosts mutation. A future repair mode must be a separate mutating
   operation with a plan and confirmation, not an automatic consequence of this
   check.
7. Emit a redacted per-path diagnostic report and record only non-secret check
   metadata/result in the operation journal. Because no mutation occurs,
   rerunning is the recovery path; an interrupted check has no rollback phase.

## 10. Command execution boundaries

Terraform, Ansible, SSH, OCI CLI (if used), and supporting tools run through one
auditable process-runner interface:

- argument lists only; never `shell=True`;
- explicit working directories;
- minimal allowlisted environment with required secret variables passed through
  without logging;
- executable discovery and minimum/maximum tested version checks;
- timeouts, cancellation, signal forwarding, bounded captured output, and
  redaction;
- separate display-safe command rendering;
- no trust in command text parsed from Terraform/Ansible output; and
- atomic writes for generated files.

Prefer the OCI Python SDK/provider APIs over scraping OCI CLI output. External
JSON is schema-validated before use.

## 11. Safety, security, and lifecycle policy

- `--dry-run` resolves and validates inputs, reconciles read-only state, and
  shows intended phases without claiming that Ansible check mode predicts every
  change. Storage dry-run may resolve a provisional backend and run read-only
  discovery on existing hosts, but it never creates attachments, emits a wipe
  token, formats, assembles RAID, mounts, or finalizes an `auto` fallback.
- `--plan` creates Terraform plans and Ansible/check previews where safe, but
  does not apply.
- Mutating operations summarize cluster UUID, topology delta, resources, and
  health checks before confirmation.
- `--yes` is allowed for controlled automation only with an additional explicit
  destructive-operation opt-in; it cannot bypass drift, identity, or health
  gates.
- Storage wipe/reuse requires a separate manifest-bound confirmation and exact
  device set after root/signature/ownership checks. General `--yes`, a Terraform
  confirmation, or an Ansible tag cannot authorize a wildcard/destructive wipe.
- Saved Terraform plans are short-lived protected artifacts bound to a state
  lineage/serial and configuration digest.
- Logs are structured, timestamped, operation-scoped, redacted, and written with
  restrictive permissions. Human and `--json` output have stable event/error
  fields.
- Never place secrets in Terraform state where a non-secret reference can avoid
  it. Mark unavoidable sensitive values and protect the entire state, not just
  outputs.
- Validate paths against symlink/traversal attacks and avoid running as root.
- Generated security rules are deny-by-default and narrowly scoped.
- Provider/API retries are bounded, classified, and use backoff; unknown outcomes
  trigger reconciliation before retry.
- Backups are not implied by infrastructure snapshots. Destructive and upgrade
  operations report the latest independently verified ScyllaDB backup status and
  require policy-defined freshness where configured.

## 12. Resumability, idempotency, and drift

Each mutating phase writes an atomic operation record. On restart, the tool does
not blindly continue: it reacquires the lock, refreshes Terraform outputs,
inventory, provider identity, storage manifest/device facts/ownership records,
and live health, then determines whether a phase is complete, safely repeatable,
or requires intervention.

Classify topology drift:

- **expected/in-progress**: matches the active operation record;
- **benign configuration drift**: can be shown and reconciled by a reviewed plan;
- **identity or membership conflict**: blocks sensitive/destructive action; or
- **orphaned infrastructure/state**: requires explicit import/recovery workflow.

Selected storage backend, device identity, ownership, and preparation-generation
drift is an identity/runtime conflict. A missing ephemeral device after
instance replacement is handled only by the replacement journal; a generic
rerun never recreates RAID or mounts over unexpected media.

Idempotency acceptance includes unchanged Terraform plans after convergence,
unchanged generated inventory bytes, and no material Ansible changes on a second
run. Do not automatically import, forget, taint, or destroy resources to resolve
drift.

## 13. Error handling and exit codes

Use typed exceptions converted once at the CLI boundary. Preserve detailed
diagnostics in protected logs while keeping terminal output concise and
redacted. Planned stable exit codes:

- `0`: success;
- `2`: CLI/configuration validation error;
- `3`: prerequisite/authentication/connectivity failure;
- `4`: state lock or concurrent-operation conflict;
- `5`: topology/state/inventory drift conflict;
- `6`: Terraform plan/apply/destroy failure;
- `7`: Ansible/configuration/orchestration failure;
- `8`: health or postcondition failure;
- `9`: user declined/cancelled operation;
- `10`: unsafe operation refused;
- `70`: unexpected internal error.

Document that subprocess details may be nested in JSON output, but the public
exit code remains operation-oriented. Keyboard interruption should stop safely,
journal the phase, and return a conventional nonzero cancellation status.

## 14. Test strategy

### Unit tests

- argparse subcommands and provider choices;
- CLI/environment/config/default precedence;
- secret redaction and absence of secret CLI options;
- cluster-name validation, traversal/symlink defenses, and canonical path safety;
- state-root precedence, Terraform directory binding, unexpected-state
  detection, and migration refusal paths;
- paired zone/count parsing, odd/asymmetric topologies, and policy validation;
- explicit/default Scylla datacenter/rack resolution, normalization,
  collision/uniqueness checks, persistence, and refusal to relabel existing
  nodes;
- stable node allocation/tombstones;
- role-specific storage-policy precedence/defaults; rejection of local NVMe for
  unsupported roles; OCI shape-capability fixture resolution; `auto`,
  `local-nvme`, and `block-volume` decisions; and fallback refusal after the
  initialization boundary;
- forced-local absent/undersized/multiple/ambiguous-device failures; explicit
  block mode excluding local NVMe; stable selection persistence; and backend/
  policy/storage-generation drift classification;
- versioned manifest serialization of required Scylla and null non-Scylla
  datacenter/rack fields plus every storage backend/device/attachment/capacity/
  encryption/performance/layout/ephemeral/retention field;
- inventory schema validation, topology hostvar/group propagation, and
  datacenter/rack/storage-manifest conflict/drift classification;
- deterministic provider-to-OS device correlation under changed enumeration
  order, absent/duplicate serials, root-on-partition/mapper/RAID ancestry,
  unexpected signatures, mounted/open holders, stale ownership markers, and
  retained-volume ownership;
- exact wipe confirmation/token validation, root-disk protection, and no
  wildcard/enumeration-order selectors in generated Ansible inputs;
- dry-run/check behavior proving storage resolution/discovery is read-only and
  that preparation, retirement, wipe, and post-initialization `auto` fallback
  are not selected;
- operation-to-playbook mapping resolution, exact catalog names, conditional
  variants, ordering, role/stable-ID limits, allowlisted extra-variable schemas,
  and fresh-inventory preconditions;
- refusal of forbidden combinations such as both live/dead removal variants,
  both in-place/reprovision OS variants, topology playbooks in check mode,
  Scylla reprovision outside `replace-node`, or any Ansible run after full
  Terraform destruction;
- confirmation and exit-code mapping;
- command construction with no shell interpolation; and
- operation journal resume decisions.

No unit test may contact real OCI, create VMs, run a real Terraform apply, or
change a real ScyllaDB cluster.

### Contract and integration tests

- Golden fixtures for supported Terraform JSON output versions, including
  datacenter/rack values, null role conventions, local-NVMe/block/boot-only
  storage manifests, Block Volume attachment/retention variants, unknown
  storage fields, and schema-upgrade failures.
- Generated inventory checked by `ansible-inventory`, with exact topology
  hostvars and expected derived datacenter/rack groups.
- A catalog contract test parses/loads the declared operation mapping and fails
  on an undefined/unmapped playbook, unsafe order, missing explicit inventory or
  limit, unapproved extra variable, stale inventory digest, or a mutating
  playbook selected for read-only `check-jump-hosts`.
- Terraform `fmt`, `validate`, and plan against mocked/test modules where
  practical.
- Ansible syntax checks, lint, check mode, and idempotence in disposable local
  containers/VMs. Loopback-device tests cover blank preparation, existing
  signatures, device-order changes, reboot-stable UUID/by-id mounts, exact
  ownership markers, check-mode no-change discovery, and refusal to reinitialize
  established storage.
- Fake process runner and provider adapters for failure, timeout, partial apply,
  stale lock, and interrupted operation scenarios.
- Optional explicitly gated OCI sandbox tests with isolated compartments,
  budgets/quotas, unique tags, teardown verification, and no production
  credentials.

### End-to-end scenarios

In an approved ephemeral environment: deploy; no-op rerun; scale out; refresh
monitoring; replace a failed node; scale in; rolling OS upgrade; interruption and
resume; drift refusal; and full destroy. Cover both a Block Volume path and,
only on a verified shape that provides it, local-NVMe loss/replacement/rebuild.
Verify retained Block Volumes survive deletion as declared and are not attached
to a different logical node. Capture topology and health evidence at each stage.

CI intent: formatting, linting, static type checking, unit tests, contract tests,
Terraform formatting/validation/security checks, Ansible lint/syntax, dependency
and secret scanning. Exact tools and commands will be selected when the
implementation and packaging files exist.

## 15. Phased milestones and acceptance criteria

### Phase 0 — contracts and scaffold

- Finalize schemas, supported Python/Terraform/Ansible/OCI versions, CLI help,
  exit codes, threat model, and topology policy.
- Acceptance: fixture-backed examples cover zero/multiple jump hosts, uneven
  zones, manager/monitor separation, explicit and provider-default
  datacenter/rack mappings, role-specific storage defaults, all three Scylla
  storage modes, and configuration precedence.

### Phase 1 — safe CLI and state foundation

- Implement parser, models, provider registry, path validation, locking,
  redaction, process runner, journals, and read-only commands.
- Acceptance: unit tests verify no secret flags, canonical external paths,
  traversal/symlink refusal, concurrency refusal, deterministic identity, and
  stable errors.

### Phase 2 — OCI Terraform provisioning

- Implement reviewed modules for network/security/compute/storage and normalized
  outputs.
- Acceptance: `fmt`/`validate` pass; sandbox plan is least-privilege; per-cluster
  isolation and lock behavior are demonstrated; output fixtures preserve the
  resolved datacenter/rack and versioned storage schemas and validate; explicit
  block mode creates only declared volumes/attachments and records disposition.

### Phase 3 — inventory and baseline Ansible

- Implement deterministic transformation, SSH trust/routing, base role, ScyllaDB,
  storage discovery/preparation/retirement, separate Manager, and monitoring
  playbooks.
- Acceptance: zero/one/multiple jump-host inventories validate; repeat Ansible
  run is idempotent; exact datacenter/rack hostvars reach Scylla configuration
  and are verified from Scylla; storage preparation excludes roots and unknown
  devices, survives device-order/reboot changes, and refuses signatures/backend
  drift; relabel drift is refused; no secret enters inventory or logs.

### Phase 4 — deploy and reconciliation

- Complete deploy, dry-run/plan/apply gates, postconditions, and resume.
- Acceptance: ephemeral cluster deploys, converges on rerun, survives a
  controlled interruption, reports injected drift before mutation, and records
  the expected ordered/limited playbook invocations with redacted variables.
  `auto` selection/fallback is demonstrated before initialization and refused
  afterward.

### Phase 5 — node lifecycle and scaling

- Add add/replace/destroy node and scale workflows.
- Acceptance: stable identities never renumber; uneven topology behaves as
  declared; add/scale preserve zone-to-rack mappings, replacement preserves the
  target's datacenter/rack, and each workflow gates on replication/topology
  health and updates Manager/monitoring. Tests prove logical Scylla topology
  playbooks finish before corresponding Terraform deletion and forbidden
  live/dead variants cannot run together. Local-NVMe replacement rebuilds from
  the cluster, while retained Block Volume reuse requires exact ownership
  validation.

### Phase 6 — maintenance and destruction

- Add redeploy, refresh-monitoring, upgrade-os, check-jump-hosts, and full
  destroy.
- Acceptance: rolling operations stop on failed health gates; destroy refuses
  conflict and removes only reviewed resources; declared Block Volume retention
  is honored, local-NVMe loss is confirmed, data disks are not reinitialized by
  redeploy/OS upgrade, and the tombstone remains.

### Phase 7 — hardening and provider extensibility

- Security review, fault injection, compatibility matrix, operator runbooks, and
  a second provider design spike without implementing unsupported behavior.
- Acceptance: operation tests use provider fakes without OCI assumptions; audit
  finds no secret persistence or shell injection path; recovery docs are tested.

## 16. Decisions to resolve before implementation

- Supported Python, Terraform, OCI provider, Ansible, ScyllaDB, Manager,
  monitoring, and guest OS version matrix.
- Region/availability-domain input and whether OCI zone aliases are accepted.
- Default network architecture, egress path, operator ingress CIDRs, IPv6, DNS,
  and private-service access.
- Concrete minimum local-device count/capacity by approved Scylla shape,
  Block Volume count/size/VPU/attachment defaults per role, and provider quota/
  cost limits.
- Version-matrix-specific RAID/filesystem/mount/data-commitlog-cache-log layout,
  local-NVMe guest-encryption support, ownership-marker format, wipe UX, Block
  Volume backup/retention defaults, CHAP secret handoff, and whether any
  retained-data migration is supported. Until resolved, no universal layout or
  automatic retained-volume reuse is promised.
- Replication/failure-domain policy and which odd/asymmetric topologies warn
  versus fail.
- Backup provider, required freshness, retention, encryption, and restore test
  policy.
- Remote-backend requirements, credential model, and migration timing; local
  state remains the initial canonical backend until that work is approved.
- Exact approved OCI auth methods and environment variable names.
- Whether configuration files are needed in v1; if so, their non-secret schema.
- Distribution model (single script checkout versus installable Python package).

## 17. Authoritative resources to consult

Validate behavior against current versions of these primary sources:

### Supplied project-specific sources

- [OCI provider for Terraform](https://registry.terraform.io/providers/oracle/oci/latest/docs)
- [ScyllaDB Ansible integration](https://docs.scylladb.com/manual/stable/using-scylla/integrations/integration-ansible.html)
- [ScyllaDB Ansible roles source](https://github.com/scylladb/scylla-ansible-roles)
- [ScyllaDB Ansible roles wiki](https://github.com/scylladb/scylla-ansible-roles/wiki)

### Terraform

- [Terraform state](https://developer.hashicorp.com/terraform/language/state)
- [State security and sensitive data](https://developer.hashicorp.com/terraform/language/state/sensitive-data)
- [Backend configuration](https://developer.hashicorp.com/terraform/language/backend)
- [State locking](https://developer.hashicorp.com/terraform/language/state/locking)
- [Workspaces](https://developer.hashicorp.com/terraform/language/state/workspaces)
- [Terraform JSON output format](https://developer.hashicorp.com/terraform/internals/json-format)
- [Terraform CLI documentation](https://developer.hashicorp.com/terraform/cli)
- [Terraform `init`](https://developer.hashicorp.com/terraform/cli/commands/init),
  [`plan`](https://developer.hashicorp.com/terraform/cli/commands/plan),
  [`apply`](https://developer.hashicorp.com/terraform/cli/commands/apply),
  [`destroy`](https://developer.hashicorp.com/terraform/cli/commands/destroy),
  and [`output`](https://developer.hashicorp.com/terraform/cli/commands/output)

### Ansible

- [Ansible inventory guide](https://docs.ansible.com/ansible/latest/inventory_guide/index.html)
- [Working with inventory](https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html)
- [Inventory plugins](https://docs.ansible.com/ansible/latest/plugins/inventory.html)
- [Developing inventory plugins](https://docs.ansible.com/ansible/latest/dev_guide/developing_inventory.html)
- [Ansible security guidance](https://docs.ansible.com/ansible/latest/reference_appendices/security.html)
- [Ansible check/diff mode](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_checkmode.html)
- [Ansible SSH connection plugin](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/ssh_connection.html)

### OCI

- [OCI documentation](https://docs.oracle.com/en-us/iaas/Content/home.htm)
- [OCI Compute shapes and local-disk capabilities](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm)
- [Protecting data on local NVMe devices](https://docs.oracle.com/en-us/iaas/Content/Compute/References/nvmedeviceinformation.htm)
- [OCI instance termination and NVMe erasure](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/terminatinginstance.htm)
- [OCI Block Volume overview](https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/overview.htm)
- [OCI Block Volume performance and VPUs](https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/blockvolumeperformance.htm)
- [Attaching Block Volumes](https://docs.oracle.com/en-us/iaas/Content/Block/Tasks/attach-compute-volume-attachment.htm)
- [OCI networking](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/overview.htm)
- [OCI network security groups](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/networksecuritygroups.htm)
- [OCI Compute instance metadata](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm)
- [OCI Compute images](https://docs.oracle.com/en-us/iaas/Content/Compute/References/images.htm)
- [OCI Bastion concepts](https://docs.oracle.com/en-us/iaas/Content/Bastion/Concepts/bastionoverview.htm)
- [OCI SDK and CLI configuration](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm)
- [OCI security best practices](https://docs.oracle.com/en-us/iaas/Content/Security/Reference/configuration_security.htm)

### ScyllaDB operations

- [ScyllaDB documentation](https://docs.scylladb.com/manual/stable/)
- [ScyllaDB cluster management](https://docs.scylladb.com/manual/stable/operating-scylla/)
- [ScyllaDB Manager documentation](https://manager.docs.scylladb.com/stable/)
- [ScyllaDB Monitoring documentation](https://monitoring.docs.scylladb.com/stable/)
- [ScyllaDB upgrade documentation](https://docs.scylladb.com/manual/stable/upgrade/)
- [Add-node/out-scale procedure](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/add-node-to-cluster.html)
- [Remove-node/down-scale procedure](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/remove-node.html)
- [Dead-node replacement procedure](https://docs.scylladb.com/manual/stable/operating-scylla/procedures/cluster-management/replace-dead-node.html)
- [ScyllaDB system configuration and storage setup](https://docs.scylladb.com/manual/stable/getting-started/system-configuration.html)
- [ScyllaDB hardware and storage requirements](https://docs.scylladb.com/manual/stable/getting-started/system-requirements.html)

Use the version-specific node add/remove/replace, rolling restart/upgrade,
repair, backup, and recovery procedures linked from those official roots. Do not
freeze operational commands in code without validating them against the target
ScyllaDB version.

### Python and security engineering

- [Python `argparse`](https://docs.python.org/3/library/argparse.html)
- [Python `logging`](https://docs.python.org/3/library/logging.html)
- [Python `subprocess`](https://docs.python.org/3/library/subprocess.html)
- [Python `unittest`](https://docs.python.org/3/library/unittest.html)
- [Python virtual environments](https://docs.python.org/3/library/venv.html)
- [Python packaging guide](https://packaging.python.org/)
- [Python packaging project metadata](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)

Deep links and upstream behavior can change. During implementation, pin versions,
record the date/version consulted, and fall back to each official documentation
root if a deep link moves.
