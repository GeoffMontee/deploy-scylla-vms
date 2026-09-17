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
  - [Environment variable registry](#environment-variable-registry)
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
  - [Common CLI flag groups](#common-cli-flag-groups)
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
python deploy_scylla_vms.py [GLOBAL_FLAGS] OPERATION [OPERATION_FLAGS]
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

This subsection is a high-level summary. The normative argparse allowlist,
requiredness, defaults, environment mapping, mutual exclusions, and
operation-specific semantics are under "Operation workflows." A subcommand
rejects every flag not explicitly included there; no operation accepts arbitrary
Terraform arguments, playbook paths, Ansible extra vars, or a generic `--force`.

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
  removal/full destroy; required whenever Block Volume or `auto` fallback can
  be selected rather than inferred during destruction.
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

For a new cluster or another value not yet persisted, non-secret settings other
than the state root resolve in this order:

1. explicit CLI option;
2. documented environment variable;
3. optional config file value, if config-file support is implemented;
4. built-in default.

An explicitly supplied CLI value therefore wins when both CLI and environment
values are present. Config-file values are defaults below environment variables.
The state root has one narrower, canonical precedence with no config-file input:
`--state-dir` > `DEPLOY_SCYLLA_VMS_STATE_DIR` > platform-aware default. The
implementation must expose the resolved non-secret configuration and absolute
state root in dry-run output.

The structured non-secret config model contains one `StoragePolicy` per host
role. CLI/environment options expose only fields in the registry below; a config
field with no approved spelling cannot be overridden through an ad hoc variable.
Scylla defaults to `auto`. Manager and monitoring use explicit Block Volumes and
never consume local NVMe implicitly. Jump hosts default to `boot-only`.

For an existing cluster, persisted cluster metadata is the baseline before these
sources are considered. A differing CLI or environment value is an identity
assertion or proposed mutation; it is accepted only by an operation whose
allowlist permits that change and only after reconciliation. Neither source may
silently retopologize, relabel, change initialized storage, replace, wipe, or
destroy resources.

### Environment variable registry

This section is the normative environment contract. Variables beginning with
`DEPLOY_SCYLLA_VMS_` are owned by this application. The separately grouped OCI,
SSH, Terraform, and Ansible names are standard tool/runtime variables that are
either narrowly passed through or set internally. Any unknown
`DEPLOY_SCYLLA_VMS_*` name is a configuration error, not an ignored typo.

Parsing is shared with the corresponding CLI/config field:

- non-secret strings are UTF-8, trimmed, and must be non-empty; opaque secret
  values are not trimmed because whitespace can be significant, but an empty
  secret is invalid and is not equivalent to unset;
- enums are trimmed and ASCII-lowercased before exact allowlist matching;
  environment booleans, if introduced, accept only `true` or `false`, while the
  current encryption switches deliberately use `enabled` or `disabled`;
- integers are canonical base-10 ASCII values with the documented zero/positive
  range; floats are finite decimal values, and all duration variables are
  seconds with no unit suffix;
- paths expand a leading `~` only, never shell syntax or embedded environment
  references, and are normalized to absolute paths before path, symlink,
  ownership, and permission validation; and
- a registry entry typed as an array or object would use strict UTF-8 JSON.
  Comma splitting is never used. The initial registry has no complex-valued
  variable because repeatable selectors/maps remain CLI/config-only.

Unset means no value was supplied. Empty, whitespace-only non-secret, malformed,
out-of-range, duplicate, unknown, or conditionally forbidden values fail before
Terraform, Ansible, SSH, or OCI execution.

#### Core and runtime

| Variable | Type / accepted syntax | Default or required behavior | CLI override | Purpose |
| --- | --- | --- | --- | --- |
| `DEPLOY_SCYLLA_VMS_CLOUD_PROVIDER` | Enum; initially `oci` | `oci` | Yes — `--cloud-provider` | Select the provider adapter. |
| `DEPLOY_SCYLLA_VMS_CLUSTER_NAME` | `[a-z][a-z0-9-]{0,62}` | Unset; required for every operation | Yes — `--cluster-name` | Select the canonical cluster identity/root. |
| `DEPLOY_SCYLLA_VMS_STATE_DIR` | Absolute or `~`-expandable path | `platformdirs.user_state_path("deploy-scylla-vms", appauthor=False)` | Yes — `--state-dir` | Select the external application state root. |
| `DEPLOY_SCYLLA_VMS_CONFIG` | Readable non-secret config path | Unset | Yes — `--config` | Load schema-validated defaults. |

#### OCI provider, network, and service placement

| Variable | Type / accepted syntax | Default or required behavior | CLI override | Purpose |
| --- | --- | --- | --- | --- |
| `DEPLOY_SCYLLA_VMS_OCI_REGION` | OCI region key | Unset; required for deploy, otherwise derived from persisted cluster config | Yes — `--oci-region` | Select/assert the deployment region. |
| `DEPLOY_SCYLLA_VMS_OCI_COMPARTMENT_ID` | Compartment OCID | Unset; required for deploy, otherwise derived from persisted cluster config | Yes — `--oci-compartment-id` | Select/assert the managed compartment. |
| `DEPLOY_SCYLLA_VMS_OCI_AUTH_MODE` | `api-key`, `instance-principal`, or `resource-principal` | Unset; required, with no implicit profile | Yes — `--oci-auth-mode` | Select the allowlisted authentication flow. |
| `DEPLOY_SCYLLA_VMS_NETWORK_MODE` | `create` or `existing` | `create` for deploy, otherwise derived from persisted cluster config | Yes — `--network-mode` | Choose managed network creation or an existing VCN. |
| `DEPLOY_SCYLLA_VMS_OCI_VCN_ID` | VCN OCID | Required with `existing`; unset/forbidden with `create` unless adoption is later designed | Yes — `--oci-vcn-id` | Select an existing VCN. |
| `DEPLOY_SCYLLA_VMS_MANAGER_ZONE` | One declared zone key | Deterministically derived from deploy zones; otherwise persisted | Yes — `--manager-zone` | Place/assert the Manager host zone. |
| `DEPLOY_SCYLLA_VMS_MONITORING_ZONE` | One declared zone key | Derived with failure-domain separation when possible; otherwise persisted | Yes — `--monitoring-zone` | Place/assert the monitoring host zone. |

Role-to-subnet maps, operator CIDRs, zones, node counts, and rack maps are
repeatable CLI/config structures and intentionally have no environment encoding.

#### Topology and instance shapes

| Variable | Type / accepted syntax | Default or required behavior | CLI override | Purpose |
| --- | --- | --- | --- | --- |
| `DEPLOY_SCYLLA_VMS_SCYLLA_DATACENTER` | Normalized topology name | Provider-derived when unset for deploy; otherwise persisted | Yes — `--scylla-datacenter` | Set/assert the stable Scylla datacenter label. |
| `DEPLOY_SCYLLA_VMS_JUMP_HOST_COUNT` | Base-10 integer `>= 0` | `0` for deploy; otherwise persisted | Yes — `--jump-host-count` | Set jump-host count; zero differs from unset. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_INSTANCE_TYPE` | OCI shape string | Unset; required for deploy, otherwise persisted new-node policy | Yes — `--scylla-instance-type` | Select/assert the Scylla shape. |
| `DEPLOY_SCYLLA_VMS_MANAGER_INSTANCE_TYPE` | OCI shape string | Unset; required for deploy, otherwise persisted | Yes — `--manager-instance-type` | Select/assert the Manager shape. |
| `DEPLOY_SCYLLA_VMS_MONITORING_INSTANCE_TYPE` | OCI shape string | Unset; required for deploy, otherwise persisted | Yes — `--monitoring-instance-type` | Select/assert the monitoring shape. |
| `DEPLOY_SCYLLA_VMS_JUMP_HOST_INSTANCE_TYPE` | OCI shape string | Required when jump-host count is positive; otherwise unset/persisted | Yes — `--jump-host-instance-type` | Select/assert the jump-host shape. |
| `DEPLOY_SCYLLA_VMS_MANAGER_COUNT` | Base-10 integer; initially exactly `1` | `1` | Yes — `--manager-count` | Make the separate Manager-host count explicit. |
| `DEPLOY_SCYLLA_VMS_MONITORING_COUNT` | Base-10 integer; initially exactly `1` | `1` | Yes — `--monitoring-count` | Make the separate monitoring-host count explicit. |

#### Storage

| Variable | Type / accepted syntax | Default or required behavior | CLI override | Purpose |
| --- | --- | --- | --- | --- |
| `DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_BACKEND` | `auto`, `local-nvme`, or `block-volume` | `auto` for deploy; otherwise persisted | Yes — `--scylla-storage-backend` | Request the pre-initialization Scylla backend. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_MIN_DEVICE_COUNT` | Base-10 integer `>= 1` | Required for `auto`/`local-nvme`; unset for explicit block | Yes — `--scylla-storage-min-device-count` | Set the local-device adequacy floor. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_MIN_TOTAL_GIB` | Positive base-10 integer GiB | Required for `auto`/`local-nvme`; unset for explicit block | Yes — `--scylla-storage-min-total-gib` | Set the usable local-capacity floor. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_LAYOUT` | `single` or `raid0` | `single` for one device; required for multiple | Yes — `--scylla-storage-layout` | Select the approved device layout. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_COUNT` | Base-10 integer `>= 1` | Required whenever block or `auto` fallback is possible | Yes — `--scylla-block-volume-count` | Declare exact data-volume count. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_SIZE_GIB` | Positive base-10 integer GiB | Required whenever block or fallback is possible | Yes — `--scylla-block-volume-size-gib` | Declare per-volume capacity. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_VPUS_PER_GB` | Provider-valid base-10 integer | Required whenever block or fallback is possible | Yes — `--scylla-block-volume-vpus-per-gb` | Declare Block Volume performance. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_ATTACHMENT_TYPE` | `iscsi` or `paravirtualized` | Required whenever block or fallback is possible | Yes — `--scylla-block-volume-attachment-type` | Select the attachment capability. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_RETENTION` | `retain` or `delete` | Required whenever block or fallback is possible | Yes — `--scylla-block-volume-retention` | Persist default removal disposition. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_KEY_ID` | KMS key OCID | Unset means OCI-managed at-rest key | Yes — `--scylla-block-volume-key-id` | Select a customer-managed key identifier. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_IN_TRANSIT_ENCRYPTION` | `enabled` or `disabled` | `disabled` pending provider/shape validation | Yes — `--scylla-block-volume-in-transit-encryption` | Request transport encryption. |
| `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_SIZE_GIB` | Positive base-10 integer GiB | Unset; required for deploy, otherwise persisted | Yes — `--manager-data-volume-size-gib` | Size Manager application storage. |
| `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_VPUS_PER_GB` | Provider-valid base-10 integer | Unset; required for deploy, otherwise persisted | Yes — `--manager-data-volume-vpus-per-gb` | Set Manager volume performance. |
| `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_ATTACHMENT_TYPE` | `iscsi` or `paravirtualized` | Unset; required for deploy, otherwise persisted | Yes — `--manager-data-volume-attachment-type` | Select Manager attachment capability. |
| `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_RETENTION` | `retain` or `delete` | `retain` for deploy; otherwise persisted | Yes — `--manager-data-volume-retention` | Persist Manager volume disposition. |
| `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_KEY_ID` | KMS key OCID | Unset means OCI-managed at-rest key | Yes — `--manager-data-volume-key-id` | Select a Manager customer-key identifier. |
| `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_IN_TRANSIT_ENCRYPTION` | `enabled` or `disabled` | `disabled` pending provider/shape validation | Yes — `--manager-data-volume-in-transit-encryption` | Request Manager transport encryption. |
| `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_SIZE_GIB` | Positive base-10 integer GiB | Unset; required for deploy, otherwise persisted | Yes — `--monitoring-data-volume-size-gib` | Size monitoring application storage. |
| `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_VPUS_PER_GB` | Provider-valid base-10 integer | Unset; required for deploy, otherwise persisted | Yes — `--monitoring-data-volume-vpus-per-gb` | Set monitoring volume performance. |
| `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_ATTACHMENT_TYPE` | `iscsi` or `paravirtualized` | Unset; required for deploy, otherwise persisted | Yes — `--monitoring-data-volume-attachment-type` | Select monitoring attachment capability. |
| `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_RETENTION` | `retain` or `delete` | `retain` for deploy; otherwise persisted | Yes — `--monitoring-data-volume-retention` | Persist monitoring volume disposition. |
| `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_KEY_ID` | KMS key OCID | Unset means OCI-managed at-rest key | Yes — `--monitoring-data-volume-key-id` | Select a monitoring customer-key identifier. |
| `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_IN_TRANSIT_ENCRYPTION` | `enabled` or `disabled` | `disabled` pending provider/shape validation | Yes — `--monitoring-data-volume-in-transit-encryption` | Request monitoring transport encryption. |

#### SSH and Ansible non-secret configuration

| Variable | Type / accepted syntax | Default or required behavior | CLI override | Purpose |
| --- | --- | --- | --- | --- |
| `DEPLOY_SCYLLA_VMS_SSH_USER` | Non-empty OS user string | Image/provider-derived for deploy; otherwise persisted | Yes — `--ssh-user` | Set/assert the remote login user. |
| `DEPLOY_SCYLLA_VMS_SSH_PUBLIC_KEY_PATH` | Readable public-key path | Required when creating hosts unless an approved provider bootstrap supplies a key | Yes — `--ssh-public-key-path` | Supply public bootstrap material only. |

The public-key path is non-secret, but its location can still disclose operator
metadata and is redacted at lower log levels.

#### Observability, maintenance, and timeouts

| Variable | Type / accepted syntax | Default or required behavior | CLI override | Purpose |
| --- | --- | --- | --- | --- |
| `DEPLOY_SCYLLA_VMS_LOG_LEVEL` | `debug`, `info`, `warning`, or `error` | `info` | Yes — `--log-level` | Set redacted diagnostic verbosity. |
| `DEPLOY_SCYLLA_VMS_LOCK_TIMEOUT_SECONDS` | Finite decimal seconds `>= 0` | `30`; zero fails immediately | Yes — `--lock-timeout-seconds` | Bound lock acquisition. |
| `DEPLOY_SCYLLA_VMS_OPERATION_TIMEOUT_SECONDS` | Positive base-10 integer seconds | `3600` | Yes — `--operation-timeout-seconds` | Bound one mutating operation. |
| `DEPLOY_SCYLLA_VMS_BOOTSTRAP_TIMEOUT_SECONDS` | Positive base-10 integer seconds | `7200` | Yes — `--bootstrap-timeout-seconds` | Bound each bootstrap/streaming gate. |
| `DEPLOY_SCYLLA_VMS_REPLACEMENT_TIMEOUT_SECONDS` | Positive base-10 integer seconds | `7200` | Yes — `--replacement-timeout-seconds` | Bound replacement streaming/health gates. |
| `DEPLOY_SCYLLA_VMS_DECOMMISSION_TIMEOUT_SECONDS` | Positive base-10 integer seconds | `7200` | Yes — `--decommission-timeout-seconds` | Bound each logical removal gate. |
| `DEPLOY_SCYLLA_VMS_MONITORING_TIMEOUT_SECONDS` | Positive base-10 integer seconds | `600` | Yes — `--monitoring-timeout-seconds` | Bound monitoring reload/restart/health checks. |
| `DEPLOY_SCYLLA_VMS_TARGET_OS_VERSION` | Approved version/release string | Unset; required for `upgrade-os` | Yes — `--target-os-version` | Declare the intended guest OS result. |
| `DEPLOY_SCYLLA_VMS_OS_PACKAGE_CHANNEL` | Approved repository/channel ID | Required for in-place or potentially in-place `auto`; forbidden for reprovision-only | Yes — `--package-channel` | Select reviewed OS packages. |
| `DEPLOY_SCYLLA_VMS_OCI_IMAGE_ID` | OCI image OCID | Required for reprovision; optional candidate for `auto`; forbidden for in-place | Yes — `--image-id` | Select a reviewed immutable image. |
| `DEPLOY_SCYLLA_VMS_HEALTH_TIMEOUT_SECONDS` | Positive base-10 integer seconds | `1800` | Yes — `--health-timeout-seconds` | Bound post-host health gates. |
| `DEPLOY_SCYLLA_VMS_REBOOT_TIMEOUT_SECONDS` | Positive base-10 integer seconds | `1800` | Yes — `--reboot-timeout-seconds` | Bound reboot/reconnect validation. |
| `DEPLOY_SCYLLA_VMS_SSH_CONNECT_TIMEOUT_SECONDS` | Positive finite decimal seconds | `10` | Yes — `--connect-timeout-seconds` | Bound each jump-host SSH attempt. |
| `DEPLOY_SCYLLA_VMS_JUMP_CHECK_TIMEOUT_SECONDS` | Positive base-10 integer seconds | `300` | Yes — `--check-timeout-seconds` | Bound the complete jump-host check. |

#### Credentials and secrets

Secrets are environment-only, have no CLI/config equivalent or built-in value,
and are consumed only when the selected auth/integration path requires them.
Identifiers and secret-file/socket paths in this table are protected metadata
even when they are not cryptographic secret bytes.

| Variable | Type / accepted syntax | Default or required behavior | CLI override | Purpose |
| --- | --- | --- | --- | --- |
| `OCI_TENANCY_OCID` | Tenancy OCID | Unset; required for `api-key` | No — environment only | Supply OCI API-key tenancy identity. |
| `OCI_USER_OCID` | User OCID | Unset; required for `api-key` | No — environment only | Supply OCI API-key user identity. |
| `OCI_FINGERPRINT` | API-key fingerprint string | Unset; required for `api-key` | No — environment only | Identify the OCI signing key. |
| `OCI_PRIVATE_KEY` | Multiline PEM private-key contents | Unset; required for `api-key` | No — environment only | Supply OCI signing material without a persistent key file. |
| `OCI_PRIVATE_KEY_PASSWORD` | Opaque passphrase | Unset; required only for an encrypted OCI key | No — environment only | Unlock the OCI API private key. |
| `OCI_RESOURCE_PRINCIPAL_VERSION` | Provider-supported version string | Unset; required in a resource-principal environment | No — environment only | Select the injected resource-principal contract. |
| `OCI_RESOURCE_PRINCIPAL_RPST` | Opaque token or provider-supported token-file reference | Unset; required for `resource-principal` | No — environment only | Supply the injected resource-principal session token. |
| `OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM` | PEM contents or provider-supported protected-file reference | Unset; required for `resource-principal` | No — environment only | Supply injected resource-principal signing material. |
| `OCI_RESOURCE_PRINCIPAL_REGION` | OCI region key | Unset; required for `resource-principal` and must match resolved region | No — environment only | Bind resource-principal context to its OCI region. |
| `DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY` | Multiline PEM/OpenSSH private-key contents | Unset; required when SSH agent authentication is unavailable | No — environment only | Supply SSH key material for a short-lived owner-only file. |
| `DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY_PASSPHRASE` | Opaque passphrase | Unset; optional only for an encrypted supplied SSH key | No — environment only | Unlock supplied SSH material through a protected helper, never argv. |
| `SSH_AUTH_SOCK` | Absolute Unix socket path | Unset; optional alternative to supplied SSH key contents | No — environment only | Use an already authenticated SSH agent. |
| `DEPLOY_SCYLLA_VMS_ANSIBLE_VAULT_PASSWORD` | Opaque password | Unset; required only when pinned Ansible content uses Vault | No — environment only | Materialize a short-lived Vault password source. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_REPOSITORY_USERNAME` | Opaque UTF-8 username | Unset; required with repository password only for an authenticated repository | No — environment only | Authenticate to a configured Scylla package repository. |
| `DEPLOY_SCYLLA_VMS_SCYLLA_REPOSITORY_PASSWORD` | Opaque password/token | Unset; required with repository username only for an authenticated repository | No — environment only | Authenticate to a configured Scylla package repository. |
| `DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN` | Opaque token | Unset; required only by a selected Manager integration schema | No — environment only | Authenticate protected Manager registration/API actions. |
| `DEPLOY_SCYLLA_VMS_MONITORING_AUTH_TOKEN` | Opaque token | Unset; required only by a selected protected monitoring integration | No — environment only | Authenticate protected monitoring API/target actions. |

API-key inputs follow the [OCI Terraform provider environment contract](https://docs.oracle.com/en-us/iaas/Content/dev/terraform/configuring.htm).
Instance-principal mode uses OCI instance metadata and therefore requires none of
the API-key variables. Resource-principal names and accepted token/reference
forms must be pinned to the selected OCI SDK/provider versions before release;
the four listed names are passed only in that mode. A user-supplied OCI config
profile or persistent private-key-path variable is not supported.

Direct SSH key contents and `SSH_AUTH_SOCK` are mutually exclusive. Encrypted key
support is accepted only after the protected passphrase helper is implemented
and tested; otherwise fail with guidance to use an SSH agent. Secret values are
never displayed, persisted, placed in Terraform inputs/state/plan, inventory,
manifests, logs, exceptions, journals, or command arguments. Paths to agent
sockets or temporary secret files are also redacted. Any downstream-required
credential file is created owner-only below a protected runtime directory,
passed only to the intended process, and reliably removed.

#### Internal subprocess environment

These are set by Python after validation. They are environment variables in
child processes but are not user configuration and cannot be overridden:

| Variable | Type / accepted syntax | Default or required behavior | CLI override | Purpose |
| --- | --- | --- | --- | --- |
| `TF_DATA_DIR` | Absolute canonical cluster Terraform data path | Always set to `<cluster-root>/terraform/.terraform` | No — application-controlled | Keep Terraform working data outside the source tree. |
| `TF_IN_AUTOMATION` | Literal `1` | Always set | No — application-controlled | Request automation-oriented Terraform output. |
| `TF_INPUT` | Literal `0` | Always set | No — application-controlled | Prevent unreviewed interactive Terraform input. |
| `OCI_AUTH` | Provider-supported auth enum derived from resolved mode | Always set by the OCI adapter | No — application-controlled | Bind Terraform to the selected auth flow. |
| `ANSIBLE_CONFIG` | Absolute generated protected config path | Always set for Ansible invocations | No — application-controlled | Prevent discovery of ambient Ansible configuration. |
| `ANSIBLE_HOST_KEY_CHECKING` | Literal `True` | Always set | No — application-controlled | Enforce SSH host-key verification. |
| `ANSIBLE_VAULT_PASSWORD_FILE` | Absolute short-lived owner-only path | Set only when the Vault password input is required | No — application-controlled | Bridge the environment secret to Ansible without argv exposure. |

The process runner starts from an empty/minimal environment, adds a validated
platform executable locale baseline, the applicable allowlisted registry
values, and these application-controlled values. It never forwards the complete
Python parent environment. Terraform argument-injection/input-variable families,
ambient CLI configuration, workspace selectors, and proxy settings; Ansible
config, callback, inventory, role/plugin path, extra-var, and SSH-argument
settings; and unlisted OCI SDK/provider settings are stripped unless a later
review adds an exact registry entry and threat-model tests. Users cannot override
state/data/backend paths, automation/input modes, inventory, host-key checking,
playbooks, callbacks/plugins, or command arguments through environment.

#### Intentionally CLI-only

No environment variable exists for `--json`, `--non-interactive`, `--dry-run`,
`--plan`, `--yes`, `--allow-destructive`, stable node/host selectors, live/dead
mode, per-operation scope/component/target lists, saved-plan or resume identity,
volume disposition overrides, wipe/reuse/recreate/relabel consent, exact
device/host/cluster confirmations, or arbitrary Terraform/Ansible/SSH behavior.
Repeatable topology/network maps and operation selection lists also remain
CLI/config-only. Non-interactive execution fails when the required explicit CLI
acknowledgement is absent; environment values can never authorize destructive
or topology-changing behavior.

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

### Common CLI flag groups

The invocation grammar is
`python deploy_scylla_vms.py [GLOBAL_FLAGS] OPERATION [OPERATION_FLAGS]`.
Argparse may technically accept global flags only before the subcommand; help
examples must use that canonical order. Non-secret values resolve CLI >
documented environment variable > non-secret config file > built-in default.
The state-root exception remains exactly CLI > environment > platform-aware
default; `--config` cannot supply it.
For an existing cluster, "Persisted" below means the value comes from canonical
cluster metadata; a supplied CLI/env/config difference is a proposed change or
identity assertion and must be explicitly supported by that operation, otherwise
reconciliation refuses it. Environment values never silently retopologize,
replace, relabel, wipe, or destroy an established cluster.

The normative registry defines shared parsing, defaults, CLI overrides, and
secret/internal process handling. Current environment-capable switches use
explicit enums such as `enabled`/`disabled`; action flags are CLI-only. Unset is
distinct from empty, and repeatable mappings remain CLI/config-only unless a
future registry entry defines strict JSON. Credentials, SSH private keys,
passwords, CHAP values, and tokens remain environment-only inputs with no CLI
flags or non-secret config keys.

#### Core flags (`core`)

Every operation accepts exactly these global selection/output flags:

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--cloud-provider` | Enum; initially `oci` | `oci` | `DEPLOY_SCYLLA_VMS_CLOUD_PROVIDER` | Select provider adapter; unsupported values fail before state access. |
| `--cluster-name` | Validated `[a-z][a-z0-9-]{0,62}` string | Required; no default | `DEPLOY_SCYLLA_VMS_CLUSTER_NAME` | Select one canonical cluster root/identity. |
| `--state-dir` | Absolute or user-expandable path | Platform-aware state root | `DEPLOY_SCYLLA_VMS_STATE_DIR` | Override canonical application state root. |
| `--config` | Readable path to non-secret config | Unset | `DEPLOY_SCYLLA_VMS_CONFIG` | Load schema-validated non-secret defaults only. |
| `--log-level` | `debug`, `info`, `warning`, or `error` | `info` | `DEPLOY_SCYLLA_VMS_LOG_LEVEL` | Set redacted diagnostic verbosity. |
| `--json` | Action boolean | `false` | No | Emit stable machine-readable events instead of human output. |
| `--lock-timeout-seconds` | Finite float, `>= 0` | `30` | `DEPLOY_SCYLLA_VMS_LOCK_TIMEOUT_SECONDS` | Bound cluster-lock acquisition; `0` means fail immediately. |
| `--non-interactive` | Action boolean | `false` | No | Disable prompts; does not authorize mutation and fails if required acknowledgements are absent. |

#### Mutating execution flags (`mutate`)

Mutating operations add this group:

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--dry-run` | Action boolean | `false` | No | Resolve/reconcile and run permitted read-only discovery only; create no saved plan or mutation. |
| `--plan` | Action boolean | `false` | No | Produce operation-appropriate protected Terraform plans where infrastructure is in scope and bounded Ansible previews where safe, then stop. |
| `--yes` | Action boolean | `false` | No | Accept ordinary reviewed mutation prompts; never satisfies exact destructive/wipe/recreate acknowledgements. |
| `--operation-timeout-seconds` | Positive integer seconds | `3600` | `DEPLOY_SCYLLA_VMS_OPERATION_TIMEOUT_SECONDS` | Bound one operation; narrower phase timeouts may be lower. |

`--dry-run` and `--plan` are mutually exclusive. `--non-interactive` without
`--yes` is valid for read-only/plan-only work, but an execution that reaches a
prompt fails rather than assuming approval. Destructive execution requires
the `destructive` group plus the operation's exact confirmation value even with
`--yes`.

#### Destructive authorization flags (`destructive`)

Only operations explicitly marked destructive accept this additional group:

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--allow-destructive` | Action boolean | `false`; required for destructive execution, optional for dry-run/plan | No | Acknowledge the operation class without bypassing target/drift/health checks. |

This is not a generic force control. It authorizes nothing without the exact
operation-specific target confirmation, and it cannot authorize storage wipe or
stateless-host recreation.

#### OCI context flags (`oci-context`)

`deploy` requires resolved OCI location values. Existing-cluster operations use
persisted values and treat supplied values as identity assertions:

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--oci-region` | OCI region key string | Required on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_OCI_REGION` | Select/assert the OCI region. |
| `--oci-compartment-id` | OCI compartment OCID | Required on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_OCI_COMPARTMENT_ID` | Select/assert the managed compartment. |
| `--oci-auth-mode` | `api-key`, `instance-principal`, or `resource-principal` | Required; no implicit profile | `DEPLOY_SCYLLA_VMS_OCI_AUTH_MODE` | Select an approved auth flow without exposing credentials. |

Auth mode selects which separately documented environment-only secrets/principal
context are required. There is no `--oci-profile`, private-key, passphrase, or
token flag.

#### Network and SSH provisioning flags (`network`)

Only operations permitted to create/reconcile network or stateless compute
accept this group:

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--network-mode` | `create` or `existing` | `create` on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_NETWORK_MODE` | Choose managed network creation versus supplied VCN/subnets. |
| `--oci-vcn-id` | VCN OCID | Required with `existing`; unset with `create` unless adopting is separately designed | `DEPLOY_SCYLLA_VMS_OCI_VCN_ID` | Select an existing VCN. |
| `--oci-subnet` | Repeatable `ROLE=OCID`; roles `scylla`, `manager`, `monitoring`, `jump-host` | Required for each deployed role with `existing`; unset with `create` | No | Map roles to existing subnets without comma parsing. |
| `--operator-cidr` | Repeatable canonical IPv4/IPv6 CIDR | Required when policy creates operator ingress; no default | No | Bound SSH/approved operator endpoint ingress. |
| `--ssh-user` | Non-empty OS user string | Image/provider-derived on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_SSH_USER` | Set/assert remote login user. |
| `--ssh-public-key-path` | Readable public-key file path | Required when creating hosts unless provider bootstrap supplies an approved key | `DEPLOY_SCYLLA_VMS_SSH_PUBLIC_KEY_PATH` | Supply public bootstrap material only. |

`--network-mode existing` requires `--oci-vcn-id` and one unique
`--oci-subnet ROLE=OCID` for every role with a nonzero host count. `create`
forbids those existing-resource selectors. Private-key input has no CLI flag.

#### Topology and placement flags (`topology`)

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--zone` | Repeatable OCI zone/availability-domain string | Required on deploy; no default | No | Declare each allowed placement zone once. |
| `--nodes-per-zone` | Repeatable `ZONE=COUNT`, integer `COUNT >= 0` | Required on deploy for every zone | No | Define desired Scylla count by exact zone key. |
| `--scylla-datacenter` | Normalized topology name | Provider-derived when unset on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_SCYLLA_DATACENTER` | Set/assert the one Scylla datacenter label. |
| `--scylla-rack` | Repeatable `ZONE=RACK` | Provider-derived for omitted deploy zones; otherwise Persisted | No | Set/assert deterministic zone-to-rack mapping. |
| `--jump-host-count` | Integer `>= 0` | `0` on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_JUMP_HOST_COUNT` | Set number of jump hosts; zero is distinct from unset. |

Zone/count and zone/rack keys must match the declared zone after provider
canonicalization; duplicates, unknown/missing keys, ambiguous aliases, and comma
lists are invalid. Lifecycle operations cannot use this group to relabel
existing Scylla nodes.

#### Instance shape flags (`shapes`)

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--scylla-instance-type` | OCI shape string | Required on deploy; new nodes otherwise Persisted | `DEPLOY_SCYLLA_VMS_SCYLLA_INSTANCE_TYPE` | Select/assert Scylla compute shape. |
| `--manager-instance-type` | OCI shape string | Required on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_MANAGER_INSTANCE_TYPE` | Select/assert Manager shape. |
| `--monitoring-instance-type` | OCI shape string | Required on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_MONITORING_INSTANCE_TYPE` | Select/assert monitoring shape. |
| `--jump-host-instance-type` | OCI shape string | Required when jump-host count is positive; otherwise unset/Persisted | `DEPLOY_SCYLLA_VMS_JUMP_HOST_INSTANCE_TYPE` | Select/assert jump-host shape. |

There are no hard-coded OCI shape defaults. Provider capability validation
occurs before planning, and a lifecycle override is accepted only where the
subcommand explicitly allows replacement/new-host configuration.

#### Scylla storage flags (`scylla-storage`)

These configure only newly provisioned Scylla data devices. Existing nodes
derive the finalized policy/manifest from cluster state; supplied differences
are blocked unless the operation explicitly defines replacement/migration.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--scylla-storage-backend` | `auto`, `local-nvme`, or `block-volume` | `auto` on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_BACKEND` | Request backend before initialization. |
| `--scylla-storage-min-device-count` | Integer `>= 1` | Required for `auto`/`local-nvme`; unset for explicit block | `DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_MIN_DEVICE_COUNT` | Set local-device adequacy floor. |
| `--scylla-storage-min-total-gib` | Positive integer GiB | Required for `auto`/`local-nvme`; unset for explicit block | `DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_MIN_TOTAL_GIB` | Set usable local-capacity floor. |
| `--scylla-storage-layout` | `single` or `raid0` | `single` for one device; required for multiple | `DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_LAYOUT` | Select an approved manifest layout. |
| `--scylla-block-volume-count` | Integer `>= 1` | Required whenever block or `auto` fallback is possible | `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_COUNT` | Declare exact OCI data-volume count. |
| `--scylla-block-volume-size-gib` | Positive integer GiB per volume | Required whenever block or fallback is possible | `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_SIZE_GIB` | Declare exact volume capacity. |
| `--scylla-block-volume-vpus-per-gb` | Provider-valid integer | Required whenever block or fallback is possible | `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_VPUS_PER_GB` | Declare performance tier without inferred claims. |
| `--scylla-block-volume-attachment-type` | `iscsi` or `paravirtualized` | Required whenever block or fallback is possible | `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_ATTACHMENT_TYPE` | Select validated attachment capability. |
| `--scylla-block-volume-retention` | `retain` or `delete` | Required whenever block or fallback is possible | `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_RETENTION` | Persist default node-removal disposition. |
| `--scylla-block-volume-key-id` | KMS key OCID | Unset means OCI-managed at-rest key | `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_KEY_ID` | Select non-secret customer-key identifier. |
| `--scylla-block-volume-in-transit-encryption` | `enabled` or `disabled` | `disabled` pending provider/shape validation | `DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_IN_TRANSIT_ENCRYPTION` | Request transport encryption explicitly. |
| `--scylla-block-volume-chap` | `enabled` or `disabled` | `disabled`; `enabled` refused until secret handoff is designed | No | Select/refuse CHAP capability without accepting a credential. |

For `auto`, local minimums and complete fallback Block Volume settings are
required together because fallback cannot invent capacity, cost, or retention.
Explicit `local-nvme` forbids Block Volume settings; explicit `block-volume`
forbids local minimums and never consumes local NVMe. Layout count constraints,
shape capabilities, and initialized-backend immutability are validated before
mutation.

#### Manager/monitoring storage flags (`service-storage`)

Manager and monitoring each use one explicit Block Volume for application data
in the initial topology; local NVMe is never selected automatically.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--manager-data-volume-size-gib` | Positive integer GiB | Required on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_SIZE_GIB` | Size Manager application-data volume. |
| `--manager-data-volume-vpus-per-gb` | Provider-valid integer | Required on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_VPUS_PER_GB` | Set Manager volume performance. |
| `--manager-data-volume-attachment-type` | `iscsi` or `paravirtualized` | Required on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_ATTACHMENT_TYPE` | Select Manager attachment capability. |
| `--manager-data-volume-retention` | `retain` or `delete` | `retain` on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_RETENTION` | Persist Manager volume disposition. |
| `--manager-data-volume-key-id` | KMS key OCID | Unset means OCI-managed at-rest key | `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_KEY_ID` | Select non-secret Manager customer-key identifier. |
| `--manager-data-volume-in-transit-encryption` | `enabled` or `disabled` | `disabled` pending provider/shape validation | `DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_IN_TRANSIT_ENCRYPTION` | Request Manager transport encryption explicitly. |
| `--monitoring-data-volume-size-gib` | Positive integer GiB | Required on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_SIZE_GIB` | Size monitoring data volume. |
| `--monitoring-data-volume-vpus-per-gb` | Provider-valid integer | Required on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_VPUS_PER_GB` | Set monitoring volume performance. |
| `--monitoring-data-volume-attachment-type` | `iscsi` or `paravirtualized` | Required on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_ATTACHMENT_TYPE` | Select monitoring attachment capability. |
| `--monitoring-data-volume-retention` | `retain` or `delete` | `retain` on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_RETENTION` | Persist monitoring volume disposition. |
| `--monitoring-data-volume-key-id` | KMS key OCID | Unset means OCI-managed at-rest key | `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_KEY_ID` | Select non-secret monitoring customer-key identifier. |
| `--monitoring-data-volume-in-transit-encryption` | `enabled` or `disabled` | `disabled` pending provider/shape validation | `DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_IN_TRANSIT_ENCRYPTION` | Request monitoring transport encryption explicitly. |

### Deploy

**CLI flags**

Applies complete groups `core`, `mutate`, `oci-context`, `network`, `topology`,
`shapes`, `scylla-storage`, and `service-storage`. `--cluster-name`, OCI
location/auth, every declared zone/count, required shapes, SSH bootstrap input,
and all conditionally required storage/network fields must resolve before
planning. The `destructive` group is not accepted.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--manager-count` | Integer; initially exactly `1` | `1` | `DEPLOY_SCYLLA_VMS_MANAGER_COUNT` | Make the initial separate Manager-host count explicit. |
| `--monitoring-count` | Integer; initially exactly `1` | `1` | `DEPLOY_SCYLLA_VMS_MONITORING_COUNT` | Make the initial separate monitoring-host count explicit. |
| `--manager-zone` | One declared zone | Deterministically derived from declared zones | `DEPLOY_SCYLLA_VMS_MANAGER_ZONE` | Place Manager without implying colocation. |
| `--monitoring-zone` | One declared zone | Deterministically derived, preferring failure-domain separation | `DEPLOY_SCYLLA_VMS_MONITORING_ZONE` | Place monitoring separately where possible. |

`--zone`, `--nodes-per-zone`, and `--scylla-rack` are independently repeatable;
their key sets are validated as documented. `--dry-run` performs capability and
configuration validation only. `--plan` may create saved Terraform plans and
read-only guest previews but never applies or initializes storage. Execution
prompts before each approved Terraform apply; `--non-interactive` requires
`--yes`.

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

**CLI flags**

Applies `core`, `mutate`, `oci-context`, the Scylla-only
`--scylla-instance-type` member of `shapes`, and `scylla-storage`. OCI, shape,
and storage values default to Persisted new-node policy; supplied values apply
only to this not-yet-created node and cannot alter existing nodes. `network`,
`topology`, `service-storage`, and `destructive` are not accepted.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--node-id` | New validated stable logical ID | Required; no default | No | Reserve exactly one non-reused node identity. |
| `--zone` | One persisted canonical zone | Required; no default | No | Select exact placement/rack mapping. |
| `--expected-rack` | Persisted normalized rack name | Persisted mapping for `--zone` | No | Assert, never override, the target rack. |
| `--cleanup` | `run` or `defer` | `run` | No | Run cleanup after healthy bootstrap or journal an explicit deferral. |
| `--bootstrap-timeout-seconds` | Positive integer seconds | `7200` | `DEPLOY_SCYLLA_VMS_BOOTSTRAP_TIMEOUT_SECONDS` | Bound bootstrap/streaming wait. |
| `--wipe-storage` | Action boolean | `false` | No | Request separately confirmed reuse wipe before initialization. |
| `--confirm-wipe-device` | Repeatable exact provider/by-id device identifier | Required for every detected device with `--wipe-storage`; otherwise forbidden | No | Bind wipe consent to the reconciled device set. |

`--wipe-storage` and at least one `--confirm-wipe-device` are required together;
the confirmations must exactly equal the preflight set. An unexpected signature
without those flags fails. `--node-id` is never generated implicitly, preserving
the single-explicit-identity distinction from `scale-out`.

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

**CLI flags**

Applies `core`, `mutate`, `oci-context`, the Scylla-only member of `shapes`, and
`scylla-storage`. Shape/storage defaults are Persisted new-node policy. It does
not accept `topology` as a whole: only the delta/desired flags below are legal,
and new zones or rack/datacenter changes are refused. `network`,
`service-storage`, and `destructive` are not accepted.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--nodes-per-zone` | Repeatable `ZONE=DESIRED_COUNT`, integer `>= 0` | Exactly one topology family required | No | Set final counts for persisted zones. |
| `--add-nodes-per-zone` | Repeatable `ZONE=ADD_COUNT`, integer `>= 1` | Exactly one topology family required | No | Express positive per-zone additions without calculating totals. |
| `--node-id` | Repeatable `ZONE=NEW_LOGICAL_ID` | Generated durable IDs when omitted; if supplied, count must equal delta | No | Predeclare stable IDs for automation/audit. |
| `--max-new-nodes` | Integer `>= 1` | `1` | No | Refuse a resolved delta larger than the acknowledged bound. |
| `--cleanup` | `run` or `defer` | `run` | No | Complete or explicitly journal post-add cleanup. |
| `--bootstrap-timeout-seconds` | Positive integer seconds | `7200` | `DEPLOY_SCYLLA_VMS_BOOTSTRAP_TIMEOUT_SECONDS` | Bound each serial bootstrap gate. |

`--nodes-per-zone` and `--add-nodes-per-zone` are mutually exclusive and one
family is required. Every mapping key must be a persisted zone, duplicate keys
are invalid, and decreases are refused. Nodes remain serial initially regardless
of `--max-new-nodes`; that flag bounds total scope, not concurrency.

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

**CLI flags**

Applies `core`, `mutate`, `destructive`, `oci-context`, the Scylla-only member
of `shapes`, and `scylla-storage`. Shape/storage values default to the failed
node's persisted policy and generation; a backend/datacenter/rack change is not
accepted. `network`, `topology`, and `service-storage` are not accepted.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--node-id` | Existing stable logical ID | Required; no default | No | Select the failed logical node. |
| `--failed-host-id` | Scylla Host ID/UUID | Required; no default | No | Bind replacement to observed dead membership identity. |
| `--reason` | Non-empty bounded text | Required; no default | No | Journal operator replacement rationale. |
| `--storage-source` | `new` or `reuse-retained` | `new` | No | Select new media or explicitly validated retained Block Volumes. |
| `--retained-volume-id` | Repeatable Block Volume OCID | Required with `reuse-retained`; otherwise forbidden | No | Identify exact retained media; never infer attachment candidates. |
| `--old-volume-disposition` | `policy`, `retain`, or `delete` | `policy` from failed node's manifest | No | Resolve old Block Volumes when new media is selected; local NVMe is always ephemeral. |
| `--wipe-storage` | Action boolean | Required with `reuse-retained`; otherwise `false` | No | Require retained media to be validated then cleared before replacement bootstrap. |
| `--confirm-wipe-device` | Repeatable exact provider/by-id identifier | Required exact preflight set with `--wipe-storage` | No | Bind destructive media reuse consent. |
| `--repair-mode` | `auto`, `required`, or `skip-if-supported` | `auto` | No | Select target-version post-replacement repair policy. |
| `--replacement-timeout-seconds` | Positive integer seconds | `7200` | `DEPLOY_SCYLLA_VMS_REPLACEMENT_TIMEOUT_SECONDS` | Bound replacement streaming/health gates. |
| `--confirm-replace-node` | Exact value of `--node-id` | Interactive prompt if unset; required with `--non-interactive` execution | No | Confirm one replacement target independently of `--yes`. |

`reuse-retained` requires all retained-volume and wipe fields together, requires
`--old-volume-disposition retain`, and still must pass ownership/signature
checks; it never starts ScyllaDB on stale data. With `storage-source=new`, old
disposition must resolve explicitly before apply.
`--allow-destructive` and exact `--confirm-replace-node` are required before the
replacement Terraform apply. Plan/dry-run may omit the confirmation and never
wipe or replace.

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

**CLI flags**

Applies `core`, `mutate`, `destructive`, and `oci-context`. All topology,
provider-resource, and storage-policy facts derive from Persisted state.
`network`, `topology`, `shapes`, `scylla-storage`, and `service-storage` are not
accepted.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--node-id` | Existing stable logical ID | Required; no default | No | Select exactly one node; never select by IP/list index. |
| `--removal-mode` | `live` or `dead` | Required; no default | No | Choose decommission versus unavailable-node procedure. |
| `--failed-host-id` | Scylla Host ID/UUID | Required with `dead`; forbidden with `live` | No | Bind dead removal to observed ring identity. |
| `--volume-disposition` | `policy`, `retain`, or `delete` | `policy` from persisted manifest | No | Resolve Block Volume handling; local NVMe remains ephemeral. |
| `--decommission-timeout-seconds` | Positive integer seconds | `7200` | `DEPLOY_SCYLLA_VMS_DECOMMISSION_TIMEOUT_SECONDS` | Bound logical removal/streaming wait. |
| `--confirm-destroy-node` | Exact value of `--node-id` | Interactive prompt if unset; required with `--non-interactive` execution | No | Confirm the exact node separately from general approval. |

Execution requires `--allow-destructive`, exact node confirmation, and a
resolved volume disposition. No environment variable may select the node,
live/dead mode, disposition override, or acknowledgement.

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

**CLI flags**

Applies `core`, `mutate`, `destructive`, and `oci-context`. It accepts only the
contraction selectors below; all other topology/storage settings are Persisted.
`network`, `topology`, `shapes`, `scylla-storage`, and `service-storage` are not
accepted.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--nodes-per-zone` | Repeatable `ZONE=DESIRED_COUNT`, integer `>= 0` | Exactly one contraction family required | No | Calculate candidates from lower final counts. |
| `--remove-node` | Repeatable stable logical ID | Exactly one contraction family required | No | Provide an explicit removal set. |
| `--selection-policy` | `highest-ordinal` | `highest-ordinal`; valid only with desired counts | No | Make deterministic candidate selection reviewable. |
| `--max-remove-nodes` | Integer `>= 1` | `1` | No | Refuse a larger contraction than explicitly bounded. |
| `--removal-mode` | Repeatable `NODE_ID=live\|dead` | Required for every selected candidate before execution | No | Prevent silent inference of removal procedure. |
| `--failed-host-id` | Repeatable `NODE_ID=HOST_UUID` | Required for every `dead` candidate; forbidden for `live` | No | Bind unavailable removal to observed Host IDs. |
| `--volume-disposition` | Repeatable `NODE_ID=policy\|retain\|delete` | `policy` for omitted selected nodes | No | Resolve per-node Block Volume handling. |
| `--decommission-timeout-seconds` | Positive integer seconds | `7200` | `DEPLOY_SCYLLA_VMS_DECOMMISSION_TIMEOUT_SECONDS` | Bound each serial removal. |
| `--confirm-scale-in` | Exact cluster name | Interactive exact prompt if unset; required with `--non-interactive` execution | No | Confirm the complete reviewed contraction. |

`--nodes-per-zone` and `--remove-node` are mutually exclusive and one is
required. Desired counts must strictly decrease and explicit IDs must match the
previewed safe candidates. Execution requires mode for every candidate,
`--allow-destructive`, and exact cluster confirmation; plan mode may stop before
mode/confirmation completion.

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

**CLI flags**

Applies `core`, `mutate`, `destructive`, and `oci-context`. All topology and
resource identities derive from Persisted state. `network`, `topology`,
`shapes`, `scylla-storage`, and `service-storage` are not accepted.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--block-volume-disposition` | `policy`, `retain`, or `delete` | `policy` per volume manifest | No | Resolve cluster data-volume disposition without affecting local-NVMe erasure. |
| `--shared-resource-disposition` | `retain` or `delete-if-owned` | `retain` | No | Protect shared VCN/network/external resources by default. |
| `--state-retention` | `keep` | `keep`; no delete value in initial CLI | No | Preserve converged state/tombstone for audit and residual-resource recovery. |
| `--diagnostic-retention` | `sanitized` or `protected-full` | `sanitized` | No | Select retained pre-destroy evidence handling. |
| `--confirm-destroy-cluster` | Exact `CLUSTER_NAME:CLUSTER_UUID` | Interactive exact prompt if unset; required with `--non-interactive` execution | No | Bind irreversible approval to both cluster identifiers. |

Execution requires `--allow-destructive` and exact cluster confirmation. `--yes`
does not supply that value. State cannot be deleted through this operation, and
no environment/config value can choose a more destructive retention outcome or
provide confirmation.

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

**CLI flags**

Always applies `core`, `mutate`, and `oci-context`. Conditional shared flags are:
`network` only with `--scope cluster --infrastructure reconcile`; Manager,
monitoring, or jump-host members of `shapes` plus `service-storage` only for the
corresponding `recreate-stateless` host. `scylla-storage`, Scylla shape changes,
and `topology` are never accepted; Scylla reprovision delegates to
`replace-node`. The `destructive` group is accepted only for
`recreate-stateless`.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--scope` | `service`, `host`, or `cluster` | Required; no default | No | Bound convergence/reconciliation scope. |
| `--target-host` | Stable logical host ID | Required with `host`; forbidden with other scopes | No | Select one host without using IP/provider ID. |
| `--component` | Repeatable enum: `base`, `scylla`, `manager-agent`, `monitoring-agent`, `manager-server`, `monitoring-stack`, `monitoring-targets`, `jump-host`, `all` | Required with `service`; role-derived with host; `all` with cluster | No | Select allowlisted playbook/tag responsibilities. |
| `--infrastructure` | `configuration-only`, `reconcile`, or `recreate-stateless` | `configuration-only` | No | Prevent implicit Terraform replacement. |
| `--restart-policy` | `never`, `if-required`, or `always` | `if-required` | No | Bound service restart behavior. |
| `--confirm-recreate-host` | Exact value of `--target-host` | Required for `recreate-stateless`; otherwise forbidden | No | Authorize only the reviewed stateless host recreation. |

`recreate-stateless` requires `scope=host`, an eligible non-Scylla role,
`--allow-destructive`, and exact host confirmation. `--component all` cannot be
combined with another component. No flag selects arbitrary playbooks, tags,
extra vars, Terraform targets, or commands.

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

**CLI flags**

Applies `core`, `mutate`, and `oci-context`. It does not accept `destructive`,
`network`, `topology`, `shapes`, or either storage group; Terraform
infrastructure mutation is forbidden.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--target` | Repeatable `targets`, `monitoring-stack`, or `manager-integration` | `targets,monitoring-stack` | No | Select bounded monitoring responsibilities. |
| `--source` | `terraform` | `terraform`; no alternate source initially | No | Require targets from reconciled Terraform output/inventory. |
| `--service-action` | `check-only`, `reload-if-supported`, or `restart` | `reload-if-supported` | No | Select validation/reload/restart behavior explicitly. |
| `--stale-target-policy` | `fail` or `remove` | `fail` | No | Refuse stale targets by default instead of silently deleting config. |
| `--confirm-monitoring-restart` | Action boolean | `false`; required for non-interactive `restart` | No | Narrowly acknowledge monitoring service restart. |
| `--monitoring-timeout-seconds` | Positive integer seconds | `600` | `DEPLOY_SCYLLA_VMS_MONITORING_TIMEOUT_SECONDS` | Bound reload/restart/discovery health checks. |

`--confirm-monitoring-restart` is forbidden unless `service-action=restart`;
interactive restart prompts when it is absent. `check-only`, `--dry-run`, and
`--plan` make no configuration change; `--plan` may use Ansible check/diff only
as an estimate.

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

**CLI flags**

Applies `core`, `mutate`, and `oci-context`. The `destructive` group is accepted
only when the resolved strategy reprovisions at least one host. Shape, network,
topology, and storage settings derive from Persisted state and are not accepted;
this operation cannot combine resizing, relabeling, or backend migration.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--strategy` | `auto`, `in-place`, or `reprovision` | `auto` | No | Select validated per-host OS path; `auto` may decide but never authorize reprovision. |
| `--target-role` | Repeatable `scylla`, `manager`, `monitoring`, or `jump-host` | Exactly one target-selector family required | No | Select all eligible hosts in explicit roles. |
| `--target-host` | Repeatable stable logical host ID | Exactly one target-selector family required | No | Select explicit hosts. |
| `--target-os-version` | Version/release string from approved matrix | Required; no default | `DEPLOY_SCYLLA_VMS_TARGET_OS_VERSION` | Declare intended guest OS result. |
| `--package-channel` | Approved repository/channel identifier | Required for in-place or potentially in-place `auto`; forbidden for reprovision-only | `DEPLOY_SCYLLA_VMS_OS_PACKAGE_CHANNEL` | Select reviewed packages without arbitrary commands. |
| `--image-id` | OCI image OCID | Required for `reprovision`; optional candidate for `auto`; forbidden for in-place | `DEPLOY_SCYLLA_VMS_OCI_IMAGE_ID` | Select reviewed immutable image. |
| `--max-unavailable` | Integer; initially exactly `1` | `1` | No | Enforce one-host-at-a-time rollout. |
| `--health-timeout-seconds` | Positive integer seconds | `1800` | `DEPLOY_SCYLLA_VMS_HEALTH_TIMEOUT_SECONDS` | Bound post-host role/cluster health gate. |
| `--reboot-timeout-seconds` | Positive integer seconds | `1800` | `DEPLOY_SCYLLA_VMS_REBOOT_TIMEOUT_SECONDS` | Bound disconnect/reconnect/reboot validation. |
| `--resume-operation` | Existing operation UUID | Unset; required to resume an interrupted journal | No | Resume only the named checkpoint after full revalidation. |
| `--confirm-reprovision-host` | Repeatable exact stable host ID | Required for every host resolved to reprovision before execution | No | Authorize immutable replacement one host at a time. |

`--target-role` and `--target-host` are mutually exclusive and one family is
required. `strategy=auto` may plan a mix, but execution stops unless every
reprovision host has exact confirmation and `--allow-destructive`; in-place
hosts do not require destructive authorization. `--resume-operation` cannot
change targets, strategy, image/channel, or policy from the journal.

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

**CLI flags**

Applies only `core` and `oci-context`. It rejects `mutate`, `destructive`,
`network`, `topology`, `shapes`, and storage groups, including `--dry-run`,
`--plan`, `--yes`, and every confirmation flag, because the operation is already
read-only.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--jump-host` | Repeatable stable jump-host logical ID | Empty list means all persisted jump hosts | No | Limit path checks to named bastions. |
| `--destination` | Repeatable `assigned`, `scylla`, `manager`, `monitoring`, or `all` | `assigned` | No | Select inventory-derived destination sets. |
| `--depth` | `bastion`, `route`, or `all-targets` | `route` | No | Bound operator-to-bastion versus end-to-end probing. |
| `--destination-check` | Repeatable `ROLE=PORT`, validated role and integer port `1..65535` | Empty list means SSH only | No | Add policy-approved TCP reachability checks without arbitrary hosts. |
| `--connect-timeout-seconds` | Positive float seconds | `10` | `DEPLOY_SCYLLA_VMS_SSH_CONNECT_TIMEOUT_SECONDS` | Bound each SSH connection attempt. |
| `--check-timeout-seconds` | Positive integer seconds | `300` | `DEPLOY_SCYLLA_VMS_JUMP_CHECK_TIMEOUT_SECONDS` | Bound the complete read-only check. |

`all` cannot be combined with another destination. Every destination comes from
validated inventory; raw addresses, arbitrary commands, host-key replacement,
firewall repair, and confirmation/mutation flags are not accepted. `--json` and
`--log-level` come from `core`.

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
- For destructive automation, `--yes` is allowed only with the additional
  operation-specific destructive opt-in/confirmation; it cannot bypass drift,
  identity, or health gates.
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

- argparse subcommands, canonical global-before-subcommand syntax, generated
  help, and exact per-operation flag/group allowlists, including rejection of
  every unrelated flag;
- generated environment-registry/CLI consistency: every CLI Environment entry
  resolves to exactly one same-type/default registry field, every `Yes` override
  names a defined compatible flag, and unknown `DEPLOY_SCYLLA_VMS_*` names fail
  as likely typos;
- CLI/environment/config/default/Persisted precedence, empty-versus-unset,
  required-without-default, explicit numeric zero, finite range checks, and
  strict UTF-8 string, enum/boolean, base-10 integer, finite-decimal duration,
  `~`-only path, and JSON array/object parsing, including malformed/empty
  values and CLI-over-environment precedence;
- repeatable `ZONE=VALUE`, `ROLE=VALUE`, and `NODE_ID=VALUE` parsing,
  canonicalization, duplicate detection, mutual exclusions, exactly-one-family
  constraints, required-together fields, and forbidden combinations;
- secret redaction and absence/rejection of credential, private-key, password,
  token, CHAP-value, arbitrary extra-var/playbook/Terraform-argument, and generic
  force CLI inputs;
- mode-specific secret requirements/redaction, OCI principal allowlisting,
  short-lived secret-file cleanup, and proof that no secret or protected path
  reaches argv, state, plan, inventory, manifest, journal, exception, or logs;
- child-process environment construction from an empty/minimal baseline,
  allowlisted per-tool pass-through, fixed internal Terraform/Ansible controls,
  and rejection/stripping of ambient argument, backend/data-directory,
  workspace, config, inventory, callback/plugin, SSH-option, and proxy
  injection;
- proof that `--yes`, destructive target IDs/modes, exact confirmations, wipe/
  recreate/relabel consent, saved-plan identity, and resume identity cannot come
  from environment or config;
- `--non-interactive` failure without the required ordinary and exact
  acknowledgements; `--dry-run`/`--plan` mutual exclusion and operation-specific
  no-mutation behavior;
- existing-cluster Persisted defaults and refusal to interpret CLI/env
  differences as implicit retopology, relabeling, backend migration, or
  infrastructure replacement;
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
- Parser-registry contract tests snapshot each subcommand's help/JSON schema and
  assert its exact common groups, operation flags, environment names, defaults,
  requiredness, and deprecation-free spelling. Documentation examples parse
  through the same registry. A generated documentation contract also verifies
  registry table columns/category membership, unique environment names,
  CLI-override existence/type/default compatibility, environment-only secret
  status, and the intentionally CLI-only denial set.
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

- Finalize schemas, supported Python/Terraform/Ansible/OCI versions, normative
  per-operation CLI registry/help, exit codes, threat model, and topology policy.
- Acceptance: fixture-backed examples cover zero/multiple jump hosts, uneven
  zones, manager/monitor separation, explicit and provider-default
  datacenter/rack mappings, role-specific storage defaults, all three Scylla
  storage modes, and configuration precedence. Every subcommand accepts only
  its documented groups/flags; the generated environment contract proves every
  supported non-secret and environment-only secret/internal variable is
  discoverable, uniquely typed, defaulted, and classified; and destructive
  acknowledgements have no env/config path.

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
- Provider-version validation of the documented OCI API-key and resource-
  principal environment contracts, including supported token/reference forms.
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
