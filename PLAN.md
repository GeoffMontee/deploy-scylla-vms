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
  - [Non-secret TOML configuration](#non-secret-toml-configuration)
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
  - [Implemented jump-host SSH hardening contract](#implemented-jump-host-ssh-hardening-contract)
  - [Implemented Manager 3.12 agent install contract](#implemented-manager-312-agent-install-contract)
  - [Implemented Manager 3.12 server install contract](#implemented-manager-312-server-install-contract)
  - [Implemented Manager local-backend preflight contract](#implemented-manager-local-backend-preflight-contract)
  - [Implemented Manager local-backend storage discovery contract](#implemented-manager-local-backend-storage-discovery-contract)
  - [Implemented Manager local-backend storage preflight contract](#implemented-manager-local-backend-storage-preflight-contract)
  - [Implemented Manager 3.12 task validation contract](#implemented-manager-312-task-validation-contract)
  - [Implemented Scylla 2026.2 monitoring-agent install contract](#implemented-scylla-20262-monitoring-agent-install-contract)
  - [Implemented Scylla Monitoring 4.16.0 stack install contract](#implemented-scylla-monitoring-4160-stack-install-contract)
  - [Implemented Scylla Monitoring 4.16.0 target-file contract](#implemented-scylla-monitoring-4160-target-file-contract)
  - [Implemented Scylla 2026.2 configuration contract](#implemented-scylla-20262-configuration-contract)
  - [Implemented Scylla 2026.2 bootstrap contract](#implemented-scylla-20262-bootstrap-contract)
  - [Implemented Scylla 2026.2 dead-node replacement contract](#implemented-scylla-20262-dead-node-replacement-contract)
  - [Implemented Scylla 2026.2 direct repair contract](#implemented-scylla-20262-direct-repair-contract)
  - [Implemented Scylla 2026.2 post-expansion cleanup contract](#implemented-scylla-20262-post-expansion-cleanup-contract)
  - [Implemented production storage-retire contract](#implemented-production-storage-retire-contract)
  - [Implemented production service-converge contract](#implemented-production-service-converge-contract)
  - [Implemented production scylla-cluster-shutdown contract](#implemented-production-scylla-cluster-shutdown-contract)
  - [Implemented production os-upgrade-preflight contract](#implemented-production-os-upgrade-preflight-contract)
  - [Implemented production os-reprovision-prepare contract](#implemented-production-os-reprovision-prepare-contract)
  - [Implemented production os-upgrade-postcheck contract](#implemented-production-os-upgrade-postcheck-contract)
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
  - [Show](#show)
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

This document is the implementation plan for the Python CLI
`deploy_scylla_vms.py`. The initial foundation now implements package/CLI
scaffolding, immutable operation and OCI-provider registries, every documented
per-operation parser allowlist, strict non-secret environment precedence,
typed/redacted environment-only protected-input intake, immutable operation
requests, locally decidable cross-field validation, canonical non-mutating
state-path validation, strict non-secret TOML defaults, immutable complete
desired-cluster specifications, explicit secure state initialization,
application locking, desired-cluster/journal persistence, redaction, stable
foundation errors, a controlled process runner, anchored Terraform
commands, strict Terraform CLI version and output/host/storage JSON contracts,
local observation/inventory reconciliation, an offline OCI input adapter,
strict tfvars persistence, and tamper-safe source-staging contracts. Local
`show` is the only implemented operation workflow. These APIs are internal and
fake-tested: no complete planning-ready Terraform source, CLI planning,
initialization, provider download, apply, destroy, OCI access, Ansible, or other
infrastructure behavior is implemented. The completed tool will provision and
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

The 12 required initial operations are:

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
| `show` | Render a provenance-aware, redacted cluster report from canonical persisted/local state with optional bounded read-only live checks. |

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

### Non-secret TOML configuration

Config-file support is finalized as strict UTF-8 TOML with schema version
`deploy-scylla-vms.config/v2`. The document contains exactly
`schema_version = "deploy-scylla-vms.config/v2"` and one `[cluster]` table.
Cluster keys use the underscore form of approved desired fields from the deploy
contract. Arrays and tables use native TOML types; strings are never coerced to
integers/booleans, comma splitting is not supported, and unknown or duplicate
fields fail.

The config may supply provider/cluster identity assertions, OCI region and
compartment, network mode/selectors, zone/count/rack structures, role counts/
placement/shapes, public SSH bootstrap references, and role storage policies.
It cannot supply the state root, config path, OCI auth mode, credentials,
private keys, secrets, log/output controls, operation selection, actions,
one-shot targets/filters, destructive/wipe/recreate consent, confirmations, or
resume/saved-plan identity. Secret-like keys, private-key material,
interpolation syntax, and include directives are rejected.

An absent config selection contributes no defaults. An explicitly selected
missing, empty, invalid, unsafe, or unsupported-version file is a configuration
error. The selected path must be absolute and canonical, contain no symlink
component, identify one singly linked regular file owned by the current POSIX
user, and not be writable by group or other. Loading is read-only and never
creates application state. For existing clusters, values remain assertions or
proposed changes against the persisted desired specification; loading a file
never applies them.

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
| `DEPLOY_SCYLLA_VMS_OCI_VCN_CIDR` | Canonical RFC 1918 IPv4 CIDR, prefix `/16` through `/30` | Required with `create`; forbidden with `existing` | Yes — `--oci-vcn-cidr` | Define the managed VCN address range without an implicit default. |
| `DEPLOY_SCYLLA_VMS_OCI_PUBLIC_JUMP_HOSTS` | Strict `true` or `false` | `false` | Yes — `--oci-public-jump-hosts` | Permit public IPs only for jump hosts when matching public subnets and operator CIDRs exist. |
| `DEPLOY_SCYLLA_VMS_MANAGER_ZONE` | One declared zone key | Deterministically derived from deploy zones; otherwise persisted | Yes — `--manager-zone` | Place/assert the Manager host zone. |
| `DEPLOY_SCYLLA_VMS_MONITORING_ZONE` | One declared zone key | Derived with failure-domain separation when possible; otherwise persisted | Yes — `--monitoring-zone` | Place/assert the monitoring host zone. |

Role-to-subnet maps, per-zone private/public subnet CIDRs, operator CIDRs, zones,
node counts, and rack maps are repeatable CLI/config structures and intentionally
have no environment encoding.

Per-role image filter environment names are
`DEPLOY_SCYLLA_VMS_SCYLLA_IMAGE_OPERATING_SYSTEM`,
`DEPLOY_SCYLLA_VMS_SCYLLA_IMAGE_OPERATING_SYSTEM_VERSION`,
`DEPLOY_SCYLLA_VMS_SCYLLA_IMAGE_VERSION_MATCH`,
`DEPLOY_SCYLLA_VMS_MANAGER_IMAGE_OPERATING_SYSTEM`,
`DEPLOY_SCYLLA_VMS_MANAGER_IMAGE_OPERATING_SYSTEM_VERSION`,
`DEPLOY_SCYLLA_VMS_MANAGER_IMAGE_VERSION_MATCH`,
`DEPLOY_SCYLLA_VMS_MONITORING_IMAGE_OPERATING_SYSTEM`,
`DEPLOY_SCYLLA_VMS_MONITORING_IMAGE_OPERATING_SYSTEM_VERSION`,
`DEPLOY_SCYLLA_VMS_MONITORING_IMAGE_VERSION_MATCH`,
`DEPLOY_SCYLLA_VMS_JUMP_HOST_IMAGE_OPERATING_SYSTEM`,
`DEPLOY_SCYLLA_VMS_JUMP_HOST_IMAGE_OPERATING_SYSTEM_VERSION`, and
`DEPLOY_SCYLLA_VMS_JUMP_HOST_IMAGE_VERSION_MATCH`. Each has the matching
lowercase CLI flag. OS and version are required for every deployed role;
version-match is `exact` by default or explicit `prefix`. No distribution is
defaulted and filter compatibility is not a ScyllaDB support claim.

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
| `DEPLOY_SCYLLA_VMS_SHOW_LIVE_TIMEOUT_SECONDS` | Positive base-10 integer seconds | `300` | Yes — `--live-timeout-seconds` | Bound all explicitly requested `show` live checks. |

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
or topology-changing behavior. `show` section/node/live/failure filters and its
exact-address disclosure flag are likewise CLI-only so ambient environment
cannot broaden a report or disclose addresses.

## 4. Architecture and module layout

Keep `deploy_scylla_vms.py` as the thin executable entry point while reusable
logic lives in the package:

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
    show.py
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
- `ShowReport`: versioned deterministic projection of desired, Terraform-
  observed, and optionally live-validated cluster facts, with per-field source,
  freshness, redaction/exposure, and unknown/not-performed status.

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
CLI-supplied stable logical IDs are 1–128 ASCII characters, begin with an
alphanumeric character, and otherwise contain only alphanumerics, `.`, `_`,
`:`, or `-`; a value that parses as an IPv4 or IPv6 address is forbidden even
when it matches that lexical grammar. Persisted-state reconciliation must also
prove that a selector names the expected role and cluster.
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

**Local provider/input/staging status (26.9.1):** the provider-neutral adapter
protocol now has exactly one implementation, OCI. It converts a validated
`ClusterSpec`, caller-supplied syntactically validated image/zone/shape/local-NVMe
capability facts, and a safely read OpenSSH public key into the strict
`deploy-scylla-vms.terraform-input.oci/v2` model. This is an offline contract:
it performs no OCI call and proves neither resource existence nor capacity.
The matching-lock `deploy-scylla-vms.tfvars/v1` store writes only
`work/cluster.auto.tfvars.json` with identity/generation/digest guards. Approved
source bundles carry an `oci-root/vN` version and deterministic per-file hashes;
the source stager transactionally replaces the canonical work tree, records
`deploy-scylla-vms.terraform-source/v1`, preserves validated tfvars, and refuses
tamper, unexpected files, symlinks, downgrade, or changes after Terraform
state/backend/provider data becomes active. A command builder can bind commands
to that exact staged bundle digest and refuses planning when its staging record
is not planning-ready.

The package exposes one active OCI Terraform root at the stable physical path
`scylla_vms/terraform/bundles/oci_root/`. The `oci-root/vN` value is a logical
immutable identity persisted with exact hashes, not a version-suffixed package
directory. During unreleased development, reviewed files evolve at the stable
path and the logical identity advances whenever compatibility requires it.
Parallel old physical roots are retained only when a future explicit migration
requires their source bytes.

Packaged `oci-root/v3` is now a planning-ready source bundle. It requires stable
Terraform `>=1.5.0,<2.0.0`, constrains OCI provider
`~>9.1.0`, includes the Terraform-generated lock selecting 9.1.0, consumes the
exact generated v2 provider-input shape, and uses provider-schema-validated
`oci_core_images` lookups keyed by role and shape. Exact or prefix OS-version
filters select one unique newest AVAILABLE image and emit stable-host-keyed
review evidence through a strict partial-output parser; zero matches,
newest-time ties, and disagreement with generated host image evidence refuse.
It also creates managed VCN, regional private subnets, NAT/private routing and,
only for enabled public jump zones, public subnets plus Internet routing. In
existing mode it creates no VCN/subnet/gateway/route resources. Role NSGs permit
only explicit operator-to-jump SSH, jump-to-private SSH, Scylla internode,
Manager-to-agent/CQL, and monitoring scrape relationships; no public client CQL
rule exists. Stateful broad outbound access supports installation/runtime, while
public ingress remains bounded. Existing-network routing and subnet suitability
are explicitly not validated by Terraform. Stable logical-ID instances,
role-specific Block Volumes and attachments, explicit retained-volume
destruction prevention, provisional local-NVMe capability manifests, and the
complete strict host/storage/image/network outputs are implemented. Terraform
does not invent guest device paths; guest discovery must finalize provisional
storage evidence before preparation.

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
    work/                       # staged reviewed .tf/lock plus generated tfvars
      cluster.auto.tfvars.json # strict generated non-secret provider input
    .terraform/                # TF_DATA_DIR provider/module/backend working data
    plugin-cache/              # explicit TF_PLUGIN_CACHE_DIR
    observed.json               # strict persisted Terraform host observation
    source.json                 # staged source version/hash/identity record
    terraform.tfstate          # initial local-backend state
    terraform.tfstate.backup
    backups/                    # immutable operation-scoped pre-apply state copies
    plans/
  ansible/
    inventory.yml
    trust.json                    # versioned confirmed host-key metadata
    known_hosts
    ssh_config                    # deterministic typed routing configuration
  operations/
  logs/
    evidence.json                # strict optional diagnostic evidence aggregate
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

The implemented local persistence foundation uses these strict schema
envelopes:

- `deploy-scylla-vms.cluster/v2` stores generation, canonical cluster UUID/name,
  OCI provider identity, canonical second-resolution UTC creation/update
  timestamps, `initial-request` provenance bound only to a sanitized SHA-256
  request digest, and an identity-matched
  `deploy-scylla-vms.desired/v2` specification. The desired schema contains
  canonical provider-supplied zone identities, explicit or
  `oci-ascii-slug/v1` datacenter/rack labels, stable initial logical IDs,
  Manager/monitoring/jump-host role placement and shapes, deny-public network
  intent with SSH public references, and role-restricted storage policies.
  Initial jump hosts are assigned over sorted canonical zones in stable
  round-robin order, preserving deterministic placement for zero, one, or
  multiple hosts until a separately versioned placement policy is introduced.
  Provider-derived rack compilation requires canonical zone identities as
  inputs and never treats unresolved user aliases as provider facts.
- `deploy-scylla-vms.operation/v1` stores operation/cluster UUIDs, registered
  operation type, generation, ordered common phase, bounded status, request and
  resume-revalidation digests, and append-only evidence entries. Evidence uses
  allowlisted result enums and non-secret summary codes rather than arbitrary
  text. Interrupted records require a fresh reconciliation digest before an
  in-progress transition, and a recorded success requires verification
  evidence. Consumers must still revalidate live/local state and never infer
  success or safe resume from the journal alone.
- `deploy-scylla-vms.ansible-operation-initiation-report/v1` is the strict
  redacted in-memory projection of the internal common-journal initiation owner.
  The entry point accepts only canonical state-root/cluster identity, one typed
  operation UUID, exact `check-jump-hosts`, its bounded typed request, and the
  matching already-held operation-named `ClusterLock`; it accepts no journal
  payload, arbitrary path, status, phase, event, plan, variable, command,
  environment, evidence, or free-form text. The caller acquires the existing
  lock in its fixed order—canonical cluster-directory flock, then canonical
  lock-file flock—and initiation acquires no nested lock. It requires the fully
  initialized owner-only layout and current schema-v2 metadata/desired identity,
  refuses another pending/in-progress/interrupted operation, and checks
  persisted sibling-cluster operation artifacts for UUID replay.
- Initiation's sole write is an atomic generation-1 record in the unchanged
  `deploy-scylla-vms.operation/v1` schema at
  `<cluster-root>/operations/<operation-uuid>.json`: exact operation/cluster
  identity, normalized non-secret request digest, `IN_PROGRESS/PLAN`, null
  resume digest, equal creation/update timestamps, and empty evidence. Empty
  evidence is an explicit initial convention meaning the offline plan has not
  yet been resolved; it does not claim validation, authorization, execution, or
  health. Under the same lock, preparation may make exactly one guarded
  same-phase generation-2 transition that appends the sole resolved PLAN
  checkpoint before binding creation. Existing journals that already contain
  that exact PLAN checkpoint remain compatible and are not rewritten.
- Only the same UUID/kind/cluster/request in that exact untouched generation-1
  state with no companion or extra history is reusable. Changed selectors,
  request, kind, cluster, or UUID scope; any companion; planned/advanced/
  terminal/ambiguous history; active-operation conflict; unsafe path; or lock
  mismatch fails closed. A failure before atomic publication leaves no journal.
  A durable journal is never automatically deleted or rolled back; later
  failures use the existing exact-prefix resume rules. The report exposes only
  created/reused/blocked state, operation UUID/kind/classification, explicit
  already-public stable-ID selectors and count, request/journal digests,
  status/phase, and bounded blockers. It remains internal and disconnected from
  the existing public write-free checker.
- `deploy-scylla-vms.ansible-operation-binding/v1` is an independently
  versioned immutable PLAN-checkpoint companion at
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-binding.json`.
  It binds the cluster and operation UUIDs, operation and effective safety
  classifications, sorted stable target IDs, normalized non-secret request
  digest, exact `deploy-scylla-vms.ansible-operation-plan/v1` schema/status/
  digest, catalog digest, packaged-source version/digest, readiness schema/
  digest/status, observation/inventory/trust generations and digests, and exact
  common-journal schema/generation/digest. Its only confirmation and execution
  states are `not-collected` and `not-started`. The matching operation lock,
  canonical cluster root, current fresh evidence, exact PLAN journal checkpoint,
  generation/digest guard, and owner-only atomic persistence are mandatory.
- `deploy-scylla-vms.ansible-operation-context/v1` is the independently
  versioned immutable canonical request-context companion at
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-context.json`.
  It is created only after the exact binding v1 record exists and before
  authorization or execution. It repeats cluster/operation identity, static
  and effective classifications, sorted selected stable IDs, normalized request
  digest, plan schema/digest, binding schema/generation/digest, and an
  independently recomputed safe intent-context digest. Its only currently
  supported operation-specific value schema is
  `deploy-scylla-vms.ansible-operation-context.check-jump-hosts/v1`, with exact
  allowlisted native fields: bounded jump-host stable IDs; destination and
  depth enums; unique role plus allowlisted integer-port checks; finite bounded
  connection timeout; and bounded integer aggregate timeout. Unknown fields,
  aliases, coercions, duplicate semantic inputs, addresses, paths, commands,
  environments, arbitrary variables, protected inputs, and unbounded values
  fail closed.
  Binding v1 remains byte-for-byte compatible and does not point back to the
  context. Creation order is common PLAN journal, binding, context, optional
  authorization, then execution. Construction proves the context's normalized
  request digest equals the binding request digest and that the existing ready
  plan equals the binding plan schema/digest. Reads repeat those checks,
  reconstruct the request without caller/environment input, re-derive
  address-bearing probes from current canonical inventory, and require the
  resolver to reproduce the bound plan digest. The record is owner-only,
  no-follow, atomic, generation/digest guarded, and semantically immutable;
  missing legacy context and any late initial context fail closed.
- `deploy-scylla-vms.ansible-operation-authorization/v1` is the independently
  versioned immutable confirmation companion at
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-authorization.json`.
  It can be created only for an unblocked ready plan under the same matching
  operation lock while the common journal remains at the exact bound PLAN
  generation/digest. It repeats the exact operation/cluster identities,
  operation/effective classifications, sorted selected stable IDs, request,
  plan, binding, catalog, packaged-source, readiness, observation, inventory,
  trust, and journal generations/digests. Proofs are separate allowlisted
  `ordinary-confirmation`, `destructive-class`, `exact-operation-scope`,
  `storage-wipe`, and `monitoring-restart` kinds, each with only a normalized
  source enum and digest. The record retains no prompt text, entered token,
  device identifier, terminal/operator identity, environment, command,
  variable value, address, key, secret, or protected path. It has no expiry
  field because this plan defines no time-based authorization lifetime; current
  evidence and exact journal/binding revalidation are always required.
  Read-only operations create no authorization record. Mutating and sensitive
  operations require ordinary interactive approval or CLI `--yes`; destructive
  operations additionally require `--allow-destructive` and the operation's
  exact PLAN-defined scope confirmation. Stateless recreation, OS reprovision,
  storage wipe, and monitoring restart retain their narrower separate proofs.
  Missing PLAN-defined tokens fail closed, and `--yes` never supplies any
  narrow or destructive proof.
- `deploy-scylla-vms.ansible-operation-preparation-report/v1` is the strict
  redacted in-memory result of the internal lock-bound checkpoint-preparation
  coordinator. The coordinator accepts only canonical cluster identity, an
  operation UUID/kind, the existing typed operation request and readiness
  context, the matching already-held operation lock, and an optional existing
  normalized confirmation outcome where class policy and a modeled context
  permit it. It loads current metadata/desired/observation/inventory/trust,
  packaged source, catalog, and exact `IN_PROGRESS/PLAN` journal state; derives
  operation-specific intents from the context allowlist; and uses the shared
  resolver and existing immutable stores in the sole order binding, context,
  then class-appropriate authorization. It never accepts a caller plan,
  command, path set, variable map, environment, inventory, or free-form prompt.
  Existing byte-identical records are revalidated and reused. A matching
  binding-only or binding-plus-context prefix may continue before execution;
  mismatches, non-PLAN or failed/interrupted/completed history, any execution
  companion, ambiguous duplicate, forbidden read-only authorization, unsafe
  path, or changed evidence/source/catalog fails closed without overwrite,
  deletion, rollback, or journal advancement. A failure before the binding
  write leaves no checkpoint; a later atomic-write failure leaves only a valid
  exact-request pre-execution prefix that may be retried with the same UUID.
  The report exposes only `created`, `reused`, `not-required`, or `blocked`
  stage states, schemas/digests, safe operation/stable IDs, blockers, and
  resumable-pre-execution truth. Initially only `check-jump-hosts` is modeled;
  every other operation returns `operation-context-unmodeled` before writes.
  The coordinator does not render files, probe tools, execute, create an
  execution companion, collect confirmation, or expose a CLI path.
- `deploy-scylla-vms.ansible-operation-execution/v1` is the independently
  versioned durable execution companion at
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-execution.json`.
  The matching operation lock and canonical cluster root are mandatory for
  every generation. Immediately before the first write, the internal handoff
  revalidates the exact request, plan, binding, catalog, packaged source,
  readiness, observation, inventory, trust, common PLAN journal, and required
  authorization; read-only operations still require authorization to be
  absent. The first generation consumes a non-read-only authorization by
  recording its exact digest and `consumed` state, or records
  `not-required` for read-only work, while durably appending one selected step
  as `started` before invoking an injected executor. Each later call may start
  at most the next deterministic selected step. Attempts bind step sequence,
  playbook, classification, stable-ID limit, variables digest, command-intent
  digest, packaged playbook-source digest, and exact per-playbook
  executor-result schema; the enclosing immutable catalog digest binds the
  catalog condition and ordering. They never retain a raw
  command, variable value, address, inventory, environment, trust material,
  protected path, stdout, or stderr.
  The strict injected-executor receipt contains only the per-playbook schema,
  step sequence/name, command digest, status, integer exit code, and a digest
  of already validated bounded result evidence. Exit zero is not sufficient.
  Attempt states are `started`, `succeeded`, `failed`, `timed-out`,
  `interrupted`, `unreachable`, and `malformed-result`. Only exact strict
  success permits the next step; every other state, including a crash that
  leaves `started`, requires manual recovery review and forbids automatic
  retry. Owner-only no-follow atomic persistence, generation/digest guards,
  immutable provenance, append-only attempts, and fail-closed transition
  checks apply. The common `deploy-scylla-vms.operation/v1` journal remains
  byte-for-byte at `IN_PROGRESS/PLAN`; it cannot safely express this
  per-step ambiguity and is not silently migrated.
- `deploy-scylla-vms.ansible-operation-resume-validation/v2` is an allowlisted
  in-memory/public validation projection, not durable execution authority.
  Offline revalidation recomputes every request, target, plan, catalog, source,
  readiness, evidence, journal, binding, and required authorization. Read-only
  operations require the authorization companion to be absent; all other
  classes require it to be present and exactly unchanged. Only
  `resumable-pre-execution` can return successfully;
  `not-resumable-confirmation-state-ambiguous`,
  `not-resumable-execution-may-have-started`,
  `not-resumable-destructive-boundary-recorded`,
  `not-resumable-interrupted`, `not-resumable-failed`,
  `not-resumable-completed`, and `not-resumable-ambiguous-history` fail closed.
  The pre-execution validator additionally refuses as
  `not-resumable-execution-may-have-started` whenever an execution companion
  exists, regardless of its latest outcome. None of these companions advances
  the common journal beyond PLAN. The handoff's narrow protocol now has one
  production-capable internal adapter to the existing controlled Ansible
  service. The adapter accepts only the resolved immutable step plus an exact
  typed current-state context, revalidates the matching operation lock,
  canonical rendered config/inventory/trust, readiness, catalog, packaged
  source and exact playbook hash, and rebuilds the anchored command-intent
  digest before using the existing service and runner. It accepts only the
  established strict per-playbook parser result and maps blocked/not-performed
  validation evidence to failure even after exit zero; only result digests and
  the exact executor receipt leave the adapter. No CLI or public operation
  registry invokes it, fake process runners cover this slice, and it implies
  neither safe automatic retry nor operation completion.
- `deploy-scylla-vms.ansible-operation-coordinator-report/v1` is the
  independently versioned in-memory projection returned by the internal
  lock-bound one-step coordinator. The entry point accepts only canonical state
  root/cluster identity, an operation UUID, the already-held matching operation
  lock, one exact sibling `ansible-playbook`/`ansible-inventory` executable pair,
  and the controlled runner. It derives all state paths; loads strict cluster,
  binding, context, journal, authorization, execution, observation, inventory,
  trust, rendered SSH/Ansible, packaged-source, and catalog state; and refuses
  malformed, unsafe, stale, completed, or recovery-required state. Before any
  tool probe it validates the context/binding, reconstructs the request and
  allowlisted ephemeral variables, re-derives addresses from current inventory,
  and checks the persisted plan digest against the binding. It then probes both
  executables, validates supported identical ansible-core versions, recomputes
  exact machine-inventory readiness and the bound plan, and invokes the existing
  handoff exactly once. All safely decidable local and toolchain checks precede
  durable `started`; the existing execution companion remains authoritative for
  every later uncertainty. The report
  contains only operation/attempt/step counts and indices, bounded states,
  context/execution schemas and digests, and retry/recovery flags, with no raw
  operation/cluster/stable IDs, paths, commands, variables, output, inventory,
  addresses, keys, or environment. The explicit context schema supports the
  bounded allowlisted read-only `check-jump-hosts`
  selector/depth/destination/check/timeout combinations. Every other operation
  kind returns
  `operation-context-unmodeled` before probing or durable intent rather than
  accepting caller-supplied context. The coordinator does not loop, finalize,
  reconcile after execution, render files, collect confirmation, or expose a
  CLI/public workflow.
- `deploy-scylla-vms.ansible-check-jump-hosts-orchestration-report/v1` is the
  independently versioned in-memory projection returned by the internal
  read-only orchestration layer. Its entry point accepts only canonical state
  root/cluster identity, one operation UUID, the matching already-held
  `check-jump-hosts` operation lock, the controlled runner, and the exact
  sibling Ansible executable pair. Before any tool probe it loads the immutable
  binding/context and common journal, requires exact read-only static/effective
  classification, ready PLAN status, absent authorization, current canonical
  evidence, and reconstructs the bound two-step `inventory-preflight` then
  `connectivity-check` plan without caller requests, plans, steps, paths,
  commands, variables, or environments. It invokes the one-step coordinator
  once for each exact next step, reloading and validating the durable execution
  companion after every call. The loop is bounded by the immutable executable
  step count; an exact succeeded prefix may continue, and an already complete
  succeeded execution is observed idempotently without another call. Started,
  failed, timed-out, interrupted, unreachable, malformed, missing, extra,
  skipped, reordered, drifted, or persistence-ambiguous state stops immediately
  and never retries. The report's orchestration states are exactly
  `steps-succeeded` and `execution-stopped`; finalization states are exactly
  `semantic-evidence-ready`, `post-verification-pending`, and `not-reached`. The
  controlled adapter now appends strict address-free semantic projections to
  owner-only
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-evidence.json`
  as `deploy-scylla-vms.ansible-operation-evidence/v1` after parser validation
  and before a successful seven-field receipt. Inventory preflight retains
  exact parity/status/counts and bound inventory/observation provenance;
  connectivity retains only selected stable IDs, bounded outcomes, and exact
  requested role/port TCP pair outcomes. Each entry binds the immutable
  request/plan/binding/context/catalog/source/readiness/observation/inventory/
  trust and exact step/result/command/playbook-source digests. The handoff
  re-reads the exact projection digest before terminal success; a missing,
  mismatched, malformed, or failed post-effect evidence write is uncertain,
  manual-recovery-required, and never retried. Complete exact evidence allows
  in-memory reconstruction of the dynamic public-v2 semantic facts and the
  `semantic-evidence-ready` state. Legacy digest-only execution remains
  `post-verification-pending` without raw-output migration. The execution and
  evidence layers themselves leave `deploy-scylla-vms.operation/v1`
  byte-for-byte at `IN_PROGRESS/PLAN`.
- `deploy-scylla-vms.ansible-operation-finalization/v1` is the independently
  versioned immutable post-verification companion at
  `<cluster-root>/operations/<operation-uuid>.ansible-operation-finalization.json`.
  Its internal entry point accepts only canonical state-root/cluster identity,
  one operation UUID, and the matching already-held `check-jump-hosts` operation
  lock. It loads and validates the binding, context, execution, evidence,
  journal, current observation/inventory/trust, reconstructed readiness,
  packaged source, and operation catalog itself; callers cannot supply reports,
  plans, evidence, commands, variables, environments, or arbitrary paths.
  Finalization is restricted to exact read-only `check-jump-hosts` with absent
  authorization, a reproduced ready plan, the exact two terminal succeeded
  attempts, no recovery/retry ambiguity, and complete current receipt-bound
  semantic projections. It reconstructs only the strict address-free successful
  result: bounded statuses/counts, selected logical IDs, and requested logical
  role/port TCP pairs already permitted by the public v2 contract. It binds the
  exact request/plan/binding/context/execution/evidence/journal/catalog/source/
  readiness/observation/inventory/trust generations and digests. IPs, hostnames,
  keys, routes, raw output, commands, variables, environments, protected paths,
  credentials, and secrets are forbidden.
- Persistence order is finalization companion first, then one guarded common
  journal transition from `IN_PROGRESS/PLAN` to `IN_PROGRESS/VERIFY` appending
  `VERIFY/completed` evidence bound to the companion digest, then one guarded
  transition to `SUCCEEDED/JOURNAL`. The common
  `deploy-scylla-vms.operation/v1` schema is unchanged. A write failure may
  leave the exact immutable companion alone or the exact VERIFY prefix; either
  resumes under the same lock without rewriting the companion or duplicating an
  event. Exact terminal re-entry is read-only. Conflicting companions, duplicate
  or reordered events, journal drift, and current provenance drift fail closed.
  A public-v2 failed destination fact is currently classified by the controlled
  adapter as a failed durable execution attempt; failed, unreachable, timed-out,
  interrupted, malformed, or started attempts therefore remain manual-recovery
  state and are never converted into a clean FAILED verification or
  auto-finalized. The returned
  `deploy-scylla-vms.ansible-operation-finalization-report/v1` is an
  independently versioned allowlist projection. This finalizer remains internal,
  performs no subprocess call, makes no general health claim, and remains
  disconnected from the public no-write workflow and all CLI wiring.
- `deploy-scylla-vms.ansible-check-jump-hosts-lifecycle-report/v1` is the
  independently versioned redacted projection returned by the narrow internal
  lifecycle coordinator. The entry point accepts canonical state-root/cluster
  identity, one operation UUID, the matching already-held `check-jump-hosts`
  operation lock, the controlled runner/executable pair, and a typed request
  only when binding/context do not yet permit durable reconstruction. It accepts
  no caller plan, step set, path, command, variable map, environment, evidence,
  finalization result, confirmation, or free-form input. An exact
  `IN_PROGRESS/PLAN` common journal from the internal initiation owner is a
  mandatory prerequisite; this coordinator neither creates nor synthesizes
  one. On a generation-1 initiation journal, its preparation component first
  appends the resolved PLAN checkpoint as generation 2 before binding/context
  creation; an already exact preplanned checkpoint remains reusable.
- The lifecycle stage machine is exact: inspect the journal/companions; prepare
  a fresh or binding-only prefix, or revalidate/reuse a complete binding/context
  prefix; drive only the remaining immutable `inventory-preflight` then
  `connectivity-check` steps; require receipt-bound semantic evidence; and call
  finalization. A succeeded execution prefix resumes at only its next step.
  Complete semantic evidence proceeds without another step. A companion-only
  finalization or exact VERIFY prefix calls only the finalizer, and terminal
  `SUCCEEDED/JOURNAL` re-entry performs no write or tool call. Every component
  is invoked at most once per lifecycle call, while the nested execution loop
  remains bounded by the immutable plan step count.
- Missing journal/request, unexpected late request, wrong kind/class, forbidden
  read-only authorization, blocked/unmodeled/drifted state, legacy digest-only
  completion, and started, failed, timed-out, interrupted, unreachable, or
  malformed execution stop before later stages. Uncertain execution remains
  manual-recovery-required and never retries; no rollback or deletion is added.
  The report contains only bounded stage states, final journal status/phase,
  execution/evidence/finalization states, retry/recovery flags, schemas,
  digests, and counts. Addresses, hostnames, keys, routes, raw output, commands,
  variables, environments, protected paths, credentials, and secrets remain
  absent. This coordinator is fake-only tested, internal, and disconnected from
  both CLI wiring and the existing public no-write workflow.
- `deploy-scylla-vms.ansible-check-jump-hosts-operation-report/v1` is the
  independently versioned strict redacted projection returned by the internal
  one-call composition coordinator. Its entry point accepts only canonical
  state-root/cluster identity, one operation UUID, the bounded typed
  `check-jump-hosts` request, the matching already-held operation-named
  `ClusterLock`, and the controlled runner/executable pair. The caller retains
  lock ownership in the established order—canonical cluster-directory flock,
  then canonical lock-file flock—and this coordinator neither acquires nor
  nests a lock.
- A missing journal or exact untouched generation-1 journal calls the existing
  initiation owner first, then calls the existing lifecycle under that same
  protected scope. An advanced exact generation-2, binding/context, succeeded
  execution, semantic-evidence, finalization-only, VERIFY, or terminal prefix
  bypasses the deliberately initial-only initiation owner, validates the
  caller request against the durable common-journal digest, and enters the
  existing lifecycle at its established resume boundary. This preserves
  initiation's refusal of companions and advanced history while allowing the
  required one-call API to resume exact durable prefixes without duplicating
  journal, preparation, execution, evidence, or finalization state machines.
- A blocked initiation never calls lifecycle. Component exceptions remain the
  existing typed application errors for stable CLI-boundary mapping; this layer
  does not format arbitrary component state or exception payloads. The report
  contains only operation/classification, bounded initiation/lifecycle/stage
  states, status/phase, counts, retry/recovery truth, schemas, and digests.
  Paths, addresses, routes, keys, commands, variables, environments, raw
  output, free-form input, credentials, and secrets are absent. Exact terminal
  re-entry invokes lifecycle for read-only revalidation but performs zero
  writes and zero tool calls. This API remains internal, has no CLI wiring, and
  does not alter the public `ClusterReadLock` checker.

All schemas reject unknown/missing fields, duplicate JSON keys, unknown schema
versions, noncanonical UUIDs/timestamps/digests, identity changes, and duplicate
or regressing generations. Updates require the expected previous generation and
byte digest. Writes use owner-only sibling temporary files, flush/fsync,
same-directory atomic replacement, directory fsync where supported, and refuse
symlink, hard-link, wrong-type, owner, or permission mismatches. The explicit
locked metadata API also proves that the matching cluster lock object is
currently acquired before a first write or update.

Directory creation is available only through an explicit internal initializer;
path derivation, CLI parsing, and operation refusal remain non-mutating. The
initializer requires the selected state root's direct parent to exist, creates
the root and canonical children with exact owner-only modes independently of
umask, and uses POSIX directory descriptors plus `O_NOFOLLOW` where available
to resist component-substitution races. Application locking currently requires
POSIX `flock` and `O_NOFOLLOW`, records only bounded PID/host/operation/time
metadata, times out without deleting the lock file, and never replaces
Terraform/backend locking.

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

The implemented Terraform CLI boundary supports stable HashiCorp Terraform
`>=1.5.0,<2.0.0` and rejects prereleases. Version 1.5 is the deliberate minimum
because it contains the complete command surface used here: global `-chdir`,
machine-readable version/validate/plan/show/output contracts, saved plans,
detailed plan exit status, explicit local state arguments, and backend lock
timeouts. The upper bound prevents an unreviewed future major from silently
changing these contracts. The partial OCI source constrains provider `~>9.1.0`
and tracks a Terraform-generated lock selecting 9.1.0; provider installation is
performed only by explicit Terraform initialization and is not connected to a
CLI workflow.

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

**Local contract status (26.9.1):** strict
`deploy-scylla-vms.observed/v1` records now persist the complete validated v1
host/storage manifest at `terraform/observed.json`, bound to cluster identity,
source, capture time, generation, and manifest digest. Deterministic local
reconciliation classifies match, intended change, drift, unknown observation,
and sensitive identity/topology/storage conflict without rewriting either
source. The implemented `deploy-scylla-vms.inventory/v1` record is JSON
(therefore valid YAML) at `ansible/inventory.yml`; it uses stable logical host
keys, static `scylla`, `manager`, `monitoring`, and `jump_hosts` groups plus
collision-checked zone/datacenter/rack groups, allowlisted hostvars, and
structured direct/ProxyJump routing references. Record metadata in `all` vars
binds it to the source manifest generation/digest. Writes are atomic,
matching-lock gated, and explicitly approved. The internal execution gate now
strictly compares `ansible-inventory --list` and `--graph` machine output with
the expected hostvars, groups, memberships, source metadata, and route fields;
unknown hosts/groups, aliases, unsafe variables, and any mismatch produce a
conflict readiness report. The independently versioned SSH trust contract
described below completes local steps 8–9 without claiming live reachability.

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

The implemented execution foundation registers every name and operation
sequence below. Exactly `inventory-preflight`, `connectivity-check`,
`routed-keyscan`, `evidence-collect`, `jump-host-configure`, `base-os`,
`deploy-reboot`,
`storage-discover`,
`storage-preflight`, `storage-prepare`, `storage-postcheck`, `scylla-install`,
`scylla-configure`, `scylla-bootstrap`, `scylla-health`, `scylla-remove-live`,
`scylla-remove-dead`, `scylla-replace-dead`, `scylla-repair`,
`scylla-cleanup`, `manager-agent`, `manager-server`, `manager-tasks`,
`manager-backend-local-install`, `manager-backend-preflight`,
`manager-backend-storage-discover`, `manager-backend-storage-preflight`,
`manager-backend-storage-prepare`,
`monitoring-agent`,
`monitoring-stack`,
`monitoring-targets`,
`storage-retire`,
`service-converge`,
`scylla-cluster-shutdown`,
`os-upgrade-preflight`,
`os-upgrade-in-place`,
`os-reprovision-prepare`,
and `os-upgrade-postcheck`
have reviewed, hash-checked packaged bodies and
`source_available=true`. All 38 catalog entries now have packaged sources. The
typed registry
export is the single machine-readable source of truth for these operation
mappings; the workflow lists below explain its order and conditions.
Names follow
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
- `ansible/playbooks/routed-keyscan.yml` — implemented read-only,
  check-mode-safe, serial-one support collection on exactly one already trusted
  jump stable ID. Python derives a bounded set of assigned RFC 1918 private
  targets and fixed port 22 from current canonical inventory; callers provide
  stable IDs only. The protected request is bound to current observation,
  inventory, trust, readiness, stable/provider identities, routes, collection
  time, and timeout policy. A `no_log` custom module invokes only canonical
  `/usr/bin/ssh-keyscan` with an argument array, no shell, fixed Ed25519 and
  NIST P-256 ECDSA types, controlled locale, and bounded timeout/output. Its
  independently versioned strict result returns only stable IDs, validated
  candidate public keys/fingerprints, bounded status/blockers, and digests.
  Raw addresses, stderr, command lines, and invocation data are never returned.
  The command environment overrides Ansible's persistent log path with
  `/dev/null` for this source so candidate keys remain in memory only.
  The controller revalidates all canonical state and route bindings before
  accepting the address-free in-memory candidate collection. It never grants
  or persists trust, modifies derived SSH files, journals an operation, or
  broadens arbitrary scanning.
- `ansible/playbooks/evidence-collect.yml` — implemented read-only, serial-five
  collection for explicitly limited stable IDs. It returns only the strict
  `deploy-scylla-vms.ansible-host-evidence/v1` projection: logical identity and
  role, OS/kernel/time/uptime, CPU/memory, approved-mount usage, block-device
  name/size/rotational shape without serials, allowlisted role service
  state/version, and bounded Scylla health status on Scylla hosts. Missing
  evidence is explicit and per-host failures are preserved. Python rejects
  unknown, malformed, duplicate, oversized, unordered, or sensitive-looking
  fields and never persists raw Ansible stdout. Collection itself does not
  write. A future operation may explicitly persist the independent
  `deploy-scylla-vms.diagnostics-evidence/v1` aggregate only at
  `<cluster-root>/logs/evidence.json`, using owner-only atomic replacement, a
  matching lock, current observation/inventory/trust bindings, and generation/
  digest guards; a failed write preserves the prior generation.
- `ansible/playbooks/jump-host-configure.yml` — implemented serial-one jump-only
  SSH hardening for exactly one validated `jump_hosts` stable ID after current
  Ubuntu `base-os` evidence, complete trust, and inventory-derived ProxyJump
  routes. It never creates VCN, NSG, route, or compute resources. Check mode is
  non-predictive. Strict `deploy-scylla-vms.ansible-jump-host-configure/v1`
  results omit addresses, raw sshd output, and configuration text.
- `ansible/playbooks/base-os.yml` — implemented serial-one minimal baseline for
  exact Ubuntu 24.04 OCI image evidence on `amd64`/guest `x86_64` or OCI/guest
  `aarch64`. It gathers bounded distribution/version/architecture facts and
  refuses unsupported evidence or any mismatch before mutation. The only
  converged packages are `ca-certificates`, `python3-debian`,
  `systemd-timesyncd`, `tar`, and `unzip`; `systemd-timesyncd` is enabled and
  started. Ubuntu's fixed reboot-required marker reports reboot requirement but
  never reboots. Check/diff mode is preview-only, stable-ID limits and current
  inventory/trust/routes are service-gated, and strict result parsing retains
  only changed/no-change/reboot-required/unsupported/failure evidence. It does
  not configure users, repositories, limits, kernel settings, swap, storage,
  ScyllaDB, firewall, SELinux, AppArmor, or SSH policy.
- `ansible/playbooks/deploy-reboot.yml` — implemented deployment-only,
  exact-one-target, serial-one/fatal, check-mode-refused Ubuntu 24.04 reboot
  support. Its operation owner derives the sole stable-ID limit and typed
  request from immutable reboot plan/authorization and successful `base-os`
  evidence. Before the built-in bounded `ansible.builtin.reboot`, it validates
  exact host/OS/architecture identity, strict host-key-checking inventory, fixed
  role-specific inactive service gates, and an in-memory hashed boot identity.
  After reconnect it requires changed boot identity, unchanged exact machine
  identity, current trust policy, the same inactive service gates, and absence
  of `/var/run/reboot-required`. Its strict
  `deploy-scylla-vms.ansible-deploy-reboot/v1` result is address-free and omits
  raw boot IDs, facts, service output, routes, keys, commands, and module output.
- `ansible/playbooks/storage-discover.yml` — read-only collection of block/NVMe,
  provider identity, root ancestry, signatures, partitions, mounts, holders,
  RAID/LVM, and ownership markers for Python manifest reconciliation.
- `ansible/playbooks/storage-preflight.yml` — implemented Scylla-only,
  serial-five, read-only reporting of Python's exact desired-policy,
  Terraform-manifest, inventory, trust, and discovery reconciliation. It
  selects only stable device identities, classifies clean-new, exactly owned
  no-op, reviewed-wipe-required, and blocked states, and binds the result to a
  cryptographic preparation-intent digest. Raw serial, WWN, volume, attachment,
  and provider identities remain protected. The playbook never discovers,
  opens, wipes, formats, assembles, mounts, or writes a device, and the result
  is return-only.
- `ansible/playbooks/storage-prepare.yml` — implemented for exactly one
  stable-ID-limited Scylla host after exact manifest/preflight validation. Its
  owner-only payload binds the operation ID, node, provider/policy/observation/
  inventory/discovery provenance, preparation-intent digest, exact protected
  device paths/identities, and device-set digest. It immediately repeats
  root/boot, mount, holder, signature, size, and stable by-id checks before the
  first write; refuses changed evidence, backend drift, `blocked`, symlinks,
  extra/missing devices, and generic confirmation; and requires separately
  bound wipe acknowledgement for `wipe-review-required`. `owned-noop` performs
  no write. The only supported policy is XFS on one exact device or RAID0 over
  the exact set, mounted by filesystem UUID at `/var/lib/scylla`; its atomic
  owner marker is written only after mount success. Check mode is refused
  rather than treated as a prediction.
- `ansible/playbooks/storage-postcheck.yml` — implemented read-only,
  check-mode-safe, serial-one verification for exactly one stable-ID-limited
  Scylla host. It immediately rediscovers the approved device set and verifies
  exact protected identities and membership, backend/layout, RAID0 state and
  members when applicable, XFS and filesystem UUID, one exact UUID-based fstab
  entry and options, the `/var/lib/scylla` mount/source/capacity/permissions,
  absence of unexpected holders/mounts/signatures, and the complete atomic
  ownership marker/provenance digests. Missing evidence or any mismatch fails
  without repair, remount, or write. Its strict
  `deploy-scylla-vms.ansible-storage-postcheck/v1` result contains only
  passed/failed/unknown checks, bounded blockers, provenance digests, hashed
  device identities, and readiness for the later Scylla slice.
- `ansible/playbooks/storage-retire.yml` — implemented Scylla-only,
  exact-one-target, serial-one, check-mode-refused retirement of previously
  prepared owned storage after proven membership absence. It revalidates hashed
  by-id identities immediately before the first irreversible step, refuses an
  active `scylla-server`, still-member authorization, blocked storage, and
  `owned-noop` rewrite-as-prepare, unmounts `/var/lib/scylla`, removes the
  UUID fstab entry, and deactivates the exact RAID0 array when present. It
  wipes only `delete` dispositions with separately bound wipe consent, never
  wipes retained or ephemeral media, and never deletes or detaches OCI
  resources or runs Terraform. Strict
  `deploy-scylla-vms.ansible-storage-retire/v1` results hash device identities
  and report mutation/recovery boundaries.
- `ansible/playbooks/scylla-install.yml` — packaged, hash-checked,
  source-available serial-one installation
  of one exact ScyllaDB 2026.2 package version on an exact Ubuntu 24.04 Scylla
  stable ID after current successful base-OS and storage-postcheck evidence.
  The wrapper owns the official signed APT repository, pins the 2026 key
  artifact and seven-package version set, masks/stops `scylla-server` before
  package work, prevents maintainer-script startup, and verifies the service
  remains masked/inactive. It does not configure topology, seeds, networking,
  storage, tuning, Manager, or Scylla files and never starts/bootstrap Scylla.
  Check mode reports `not-predicted`. The vendored public key is authenticated
  by the full issuer fingerprint in the official signed repository metadata,
  matching immutable official documentation and installer-source key-ID
  references; package intent fails if its digest or OpenPGP identity changes.
- `ansible/playbooks/scylla-configure.yml` — packaged, hash-checked,
  source-available serial-one configuration of explicitly limited Scylla stable
  IDs after exact current base-OS, storage-postcheck, package-install,
  observation, inventory, and trust evidence. Wrapper-owned templates atomically
  own only `/etc/scylla/scylla.yaml` and
  `/etc/scylla/cassandra-rackdc.properties`, with exact allowlisted keys and
  root-owned `0644` modes. Python validates normalized cluster/datacenter/rack
  labels, immutable configured identity, RFC 1918 private addresses, fixed
  storage directories, and a deterministic bounded stable-ID seed policy.
  Check mode reports `not-predicted`; the service remains masked and inactive,
  and runtime validation is explicitly not performed. This playbook does not
  install packages, tune the host, start Scylla, bootstrap membership, or claim
  health.
- `ansible/playbooks/scylla-health.yml` — implemented read-only,
  check-mode-safe, serial-five ring, membership, schema, datacenter/rack,
  streaming, service, local API/CQL reachability, and prior storage-readiness
  gates. The normal policy queries every exact Scylla stable ID, derives the
  stable-ID/Host-ID map from each node's local `nodetool info`, and compares
  normalized `status`, `describecluster`, and `netstats` views without
  returning addresses or raw output. One known coordinator is permitted only
  with a complete unique prior Host-ID map. Missing, extra, duplicate,
  transitional, moving, leaving, joining, down, topologically inconsistent, or
  cross-view-inconsistent members fail closed. The strict
  `deploy-scylla-vms.ansible-scylla-health/v1` result binds current observation,
  inventory, trust, and per-node storage evidence and provides class-specific
  blockers. Keyspace replication, quorum, capacity beyond persisted validated
  storage, and Manager backup policy are explicitly unknown or not performed
  without authenticated CQL/Manager evidence; they are never inferred healthy.
- `ansible/playbooks/manager-agent.yml` — packaged, hash-checked,
  source-available serial-one installation of one exact ScyllaDB Manager 3.12
  `scylla-manager-agent` package on an exact Ubuntu 24.04 Scylla stable ID after
  current successful base-OS and `scylla-install` evidence. It reuses the
  already-authenticated 2026 public signing key because that key signs the
  official Manager 3.12 InRelease, pins the official Ubuntu Manager 3.12 APT
  repository, prevents maintainer-script startup, and leaves
  `scylla-manager-agent` disabled and inactive. It does not write `auth_token`,
  run `scyllamgr_agent_setup`, start the agent or Scylla, configure HTTPS bind
  addresses, or verify server-to-agent reachability. Check mode reports
  `not-predicted`. Strict `deploy-scylla-vms.ansible-manager-agent/v1` results
  keep configuration, token, helper-slice, and reachability as explicit
  false/not-performed. Token handoff, helper-slice setup, agent start, and
  reachability remain later slices.
- `ansible/playbooks/monitoring-agent.yml` — packaged, hash-checked,
  source-available serial-one installation of the exact ScyllaDB 2026.2
  `scylla-node-exporter` package on one Ubuntu 24.04 Scylla stable ID after
  current successful `base-os` and `scylla-install` evidence. Official
  Monitoring docs scrape `node_exporter` on each Scylla server and the
  administration guide documents optional port `9100`. This slice reuses the
  already-authenticated 2026 key and the official Ubuntu Scylla 2026.2
  repository, prevents maintainer-script startup, and leaves
  `scylla-node-exporter` disabled and inactive because starting it would
  require an unreviewed listen-address or public-bind decision. Official
  process-exporter is not a documented per-node Ubuntu package, so it is not
  installed. The playbook does not write exporter configuration, generate
  target files, install the monitoring stack, register Manager, or start
  Scylla. Check mode reports `not-predicted`. Strict
  `deploy-scylla-vms.ansible-monitoring-agent/v1` results keep listen policy
  as `not-started` and stack/targets/process-exporter/registration/startup as
  explicit false.
- `ansible/playbooks/manager-server.yml` — packaged, hash-checked,
  source-available serial-one installation of exact ScyllaDB Manager 3.12
  `scylla-manager-server` and `scylla-manager-client` packages on one Ubuntu
  24.04 manager stable ID after current successful `base-os` evidence. It
  reuses the already-authenticated 2026 public signing key because that key
  signs the official Manager 3.12 InRelease, pins the official Ubuntu Manager
  3.12 APT repository, prevents maintainer-script startup, and leaves
  `scylla-manager` masked and inactive. Official install pages configure a
  local or remote Scylla backend, run `scyllamgr_setup`, and start the service
  only after packages; this slice stops after packages. It does not install a
  local Scylla backend, edit `scylla-manager.yaml`, run `scyllamgr_setup`,
  persist an environment token, register a cluster, create tasks, or start
  Manager. Check mode reports `not-predicted`. Strict
  `deploy-scylla-vms.ansible-manager-server/v1` results keep backend,
  registration, setup, and startup as explicit false. Backend configuration,
  registration, and task creation remain later slices.
- `ansible/playbooks/manager-backend-preflight.yml` — packaged, hash-checked,
  source-available read-only inspection of one exact Manager stable ID after
  current Ubuntu 24.04/base-OS, Manager 3.12 install, activation/backend-plan,
  inventory, trust, readiness, and source provenance. It is serial-one, fatal,
  and check-mode-safe. It inspects only bounded OS/architecture, CPU/memory/root
  capacity, approved-mount counts, fixed local Scylla and Manager package/
  service states, reboot requirement, and loopback availability. It performs
  no repository query, arbitrary file/config/device/process/environment
  collection, network/CQL/schema action, package/configuration mutation, setup,
  or service start. Strict
  `deploy-scylla-vms.ansible-manager-backend-preflight/v1` results are
  address/path/configuration/credential/secret-free and report readiness only
  for a later reviewed local-backend installation plan; backend operational
  readiness and every unresolved package/storage/tuning/capacity/setup/schema/
  recovery gate remain blocked or not-performed.
- `ansible/playbooks/manager-backend-local-install.yml` — packaged,
  hash-checked, source-available package-only installation of the exact
  ScyllaDB 2026.2 seven-package set on one Ubuntu 24.04 Manager stable ID for
  the selected local-one-node backend. It requires the immutable backend
  installation context/plan, successful backend-preflight reconciliation,
  exact Manager/base-OS evidence, identified dedicated-backend-storage
  provenance, current observation/inventory/trust/source bindings, and the
  authenticated vendored 2026 key/repository provenance. It is serial-one,
  fatal, and check-mode preview-only. It prevents maintainer-script startup,
  masks/stops `scylla-server` before package work, and leaves it
  masked/inactive. It does not invoke the upstream Scylla role or reuse the
  Scylla-role storage prerequisite, and it performs no setup, tuning, storage/
  filesystem/mount mutation, configuration, CQL/schema/keyspace work, Manager
  configuration/registration/tasks, token handling, or service start.
- `ansible/playbooks/manager-backend-storage-discover.yml` — packaged,
  hash-checked, source-available read-only discovery of one exact dedicated
  Manager-role Block Volume after immutable storage-allocation planning. It is
  manager-only, exact-one-target, serial-one, fatal, and check-mode-safe. It
  correlates only non-path guest identities against the exact Terraform
  storage manifest and inspects bounded block, mount, signature, holder,
  ownership-marker, and topology facts. Missing, ambiguous, root/boot,
  local-NVMe, mounted, held, shared, wrong-size, or provenance-conflicting
  candidates fail closed. Strict
  `deploy-scylla-vms.ansible-manager-backend-storage-discovery/v1` results
  contain only bounded states and hashed device/topology/manifest/provenance
  digests; raw paths, serials, UUIDs, addresses, provider IDs, commands,
  output, environment, credentials, and secrets are absent. The source never
  writes, wipes, partitions, creates RAID/filesystems, mounts, edits fstab,
  configures or starts services, or accesses CQL.
- `ansible/playbooks/manager-backend-storage-preflight.yml` — packaged,
  hash-checked, source-available read-only reconciliation of the exact Manager
  dedicated Block Volume after immutable preflight planning and successful
  discovery. It is Manager-only, exact-one-target, serial-one, fatal, and
  check-mode-safe. It compares the approved single whole-device XFS,
  `/var/lib/scylla`, fstab/mount, one-node-marker intent with bounded current
  host facts and classifies only `owned-noop`, `prepare-required`, or
  `blocked`. A blank exact unowned device requires no wipe; a signature on an
  unowned device is foreign, blocks preparation, and reports a separate future
  wipe requirement. Foreign ownership, unexpected mount/fstab/marker state,
  root/boot ancestry, holders, partitions, ambiguity, and identity/size/
  topology conflicts block. Strict
  `deploy-scylla-vms.ansible-manager-backend-storage-preflight/v1` results
  retain only bounded states/counts/booleans and hashed device-set/
  preparation-intent/blocker/provenance digests. The source never writes,
  wipes, partitions, creates RAID/filesystems, mounts, edits fstab or markers,
  configures/starts services, runs setup, or accesses CQL.
- `ansible/playbooks/manager-backend-storage-prepare.yml` — packaged,
  hash-checked, source-available destructive preparation of exactly one
  preflight-derived Manager-local dedicated Block Volume. It is Manager-only,
  exact-one-target, serial-one, fatal, and refuses check mode. Immediately
  before the first write it revalidates the exact manifest/device identity,
  requested/observed/discovered allocation equality, signatures, ownership,
  holders, root/boot ancestry, mounts, and fstab state. Its only reviewed
  layout is whole-device XFS mounted at `/var/lib/scylla` by stable UUID, with
  root ownership/mode and the Manager-local ownership marker. RAID, LVM,
  partitions, local NVMe, root fallback, package/tuning/configuration/service/
  CQL/schema/setup/registration/task work are forbidden. A wipe is allowed
  only for the exact preflight-classified wipe scope with separate digest-bound
  consent; generic approval never supplies it. `owned-noop`, blocked, retained,
  root/boot, NVMe, foreign-owned, ambiguous, or blank storage is never wiped.
  Strict
  `deploy-scylla-vms.ansible-manager-backend-storage-prepare/v1` results omit
  raw paths, serials, UUIDs, addresses, provider IDs, commands, variables,
  output, environment, credentials, and secrets. No operation authorization or
  execution owner invokes this source yet.
- `ansible/playbooks/monitoring-stack.yml` — packaged, hash-checked,
  source-available serial-one installation of the exact Scylla Monitoring
  4.16.0 archive on one Ubuntu 24.04 monitoring stable ID after current
  successful `base-os` evidence. Official docs download that tagged GitHub
  archive, require Docker, then start Grafana/Prometheus/Alertmanager with
  public UI ports and default Grafana admin/anonymous auth. This slice
  digest-checks the official 4.16.0 archive only, verifies the tagged
  `versions.sh` component pins (Prometheus v3.14.0, Grafana 13.2.0,
  Alertmanager v0.34.0, Loki 3.7.7, Promtail 3.6.11) and 2026.2 dashboard
  support, and leaves Docker uninstalled/inactive because startup would
  require unreviewed listen-address, Grafana auth, Compose secrets, and
  unsigned image-pull decisions. It does not generate scrape targets,
  install node-exporter, register Manager, start Scylla, or persist
  secrets. Check mode reports `not-predicted`. Strict
  `deploy-scylla-vms.ansible-monitoring-stack/v1` results keep listen
  policy as `not-started` and targets/auth/public-bind/Compose/containers/
  Manager/Scylla/secrets as explicit false.
- `ansible/playbooks/monitoring-targets.yml` — packaged, hash-checked,
  source-available serial-one generation of official Scylla Monitoring 4.16.0
  Prometheus target files on one Ubuntu 24.04 monitoring stable ID after
  current successful `base-os` and `monitoring-stack` evidence. It writes
  `prometheus/scylla_servers.yml` from RFC 1918 Scylla inventory identities
  with cluster/dc labels and no default ports, writes the required
  `prometheus/scylla_manager_servers.yml` as Manager `host:5090`, and reuses
  the Scylla file for official `node_exporter_servers.yml` and
  `scylla_manager_agents.yml` names. It does not start Docker, Prometheus,
  Grafana, Alertmanager, or node_exporter, does not bind UI ports, does not
  install the stack or agents, does not register Manager, and does not start
  Scylla. Check mode reports `not-predicted`. Strict
  `deploy-scylla-vms.ansible-monitoring-targets/v1` results omit addresses and
  file contents, keep listen policy `not-started`, and keep scrape-readiness
  as `not-performed` because exporters and the stack remain unstarted.
- `ansible/playbooks/manager-tasks.yml` — packaged, hash-checked,
  source-available serial-one fail-closed validation of PLAN
  `inspect`/`quiesce`/`resume`/`validate` actions on one Ubuntu 24.04 manager
  stable ID after current successful `base-os` and `manager-server` evidence.
  Official Manager 3.12 `sctool tasks`, `sctool suspend --cluster`,
  `sctool resume --cluster`, `sctool backup`, and `sctool repair` require a
  running Manager API and a registered cluster. This slice never starts or
  unmasks Manager, never writes tokens or `scylla-manager.yaml`, never
  registers a cluster, and never invokes those commands. PLAN does not define
  desired backup locations or repair schedules, so those schemas are not
  invented. Check mode reports `not-predicted`. Strict
  `deploy-scylla-vms.ansible-manager-tasks/v1` results keep `applied=false`
  and report backup/repair task work as not-performed with exact inactive/
  unregistered/backend blockers. Default action is read-only inspection.
- `ansible/playbooks/scylla-bootstrap.yml` — packaged, hash-checked,
  source-available exact-one-target first start. Its two explicit modes are
  `initial-seed` for a reviewed empty new cluster and `join-existing` for an
  exact add/scale intent with healthy surviving members and seeds. It
  revalidates all digest-bound prerequisites before systemd unmask/start and
  waits boundedly for CQL plus argv-form `nodetool` Up Normal, datacenter/rack,
  Host ID, streaming, and schema evidence. Check mode is refused.
- `ansible/playbooks/scylla-remove-live.yml` — implemented exact-one-target,
  serial-one live decommission after fresh full-cluster health and independently
  validated replication, quorum, post-removal capacity, and backup-policy
  evidence all pass. Its destructive authorization binds cluster/operation,
  stable ID, Host ID, provider ID, datacenter/rack, desired removal intent,
  health generation/digest, current observation/inventory/trust/config/storage
  digests, and the exact intended post-removal topology; general approval alone
  is insufficient. It revalidates the target identity from both target and a
  healthy survivor immediately before argv-form `nodetool decommission`, then
  polls a surviving coordinator until target absence, survivor Up Normal state,
  schema agreement, idle streaming, and exact topology agree. Check mode is
  refused. A started command is an irreversible journal/recovery boundary:
  interruption or failure blocks blind retry and preserves the host,
  infrastructure, storage, desired state, and Terraform state for diagnosis.
- `ansible/playbooks/scylla-remove-dead.yml` — perform the ScyllaDB 2026.2
  unavailable-node removal for one confirmed permanently down Host ID from one
  explicitly selected healthy surviving coordinator. The packaged source
  requires independent target unreachability and unchanged logical/provider/
  Host-ID evidence, consistent survivor ring views, fresh survivor health and
  all-passed replication/quorum/capacity/backup gates, exact intended
  post-topology, and narrow digest-bound destructive authorization. It
  revalidates the required survivor quorum immediately before exact argv-form
  `nodetool removenode <host-id>`, never contacts the dead target or invokes
  force completion, and polls supported status/read commands until exact
  absence, survivor Up Normal state, schema agreement, idle streaming, and
  topology are proven. A started command is a journal/recovery boundary and
  cannot be retried blindly.
- `ansible/playbooks/scylla-replace-dead.yml` — run the ScyllaDB 2026.2
  `replace_node_first_boot` procedure on exactly one newly provisioned
  replacement stable logical target. It requires a quorum-confirmed DN old Host
  ID, independently unreachable old provider identity, reviewed old-to-new
  stable-ID mapping, distinct new provider identity, fresh empty storage, exact
  package/config/topology/seeds, current observation/inventory/trust, all-passed
  replication/quorum/capacity/backup evidence, and narrow digest-bound
  authorization. It immediately revalidates survivors and the replacement,
  atomically adds only the UUID-valued first-boot key while the service is
  masked/inactive, then crosses one systemd unmask/start boundary. Bounded
  survivor `gossipinfo`, `status`, `netstats`, and schema checks must prove a
  new Host ID is UN, the old Host ID is absent, streaming is complete, and
  exact post-topology agrees. It never runs `removenode`, repair, force,
  infrastructure, or storage mutation. The key is retained after success;
  repair remains required unless strict complete RBNO evidence proves otherwise.
- `ansible/playbooks/scylla-cleanup.yml` — run post-scale cleanup serially on the
  Python-computed eligible host limit and verify completion before future node
  removal.
- `ansible/playbooks/scylla-repair.yml` — run and verify the
  direct 2026.2 full-repair variant on exactly one explicitly limited stable ID
  after replacement or an operator-reviewed bootstrap. A future Manager task
  may satisfy the same gate through a separate evidence contract.
- `ansible/playbooks/service-converge.yml` — implemented fail-closed serial-one
  role-aware systemd reconcile for one explicitly selected service scope. It
  requires Ubuntu 24.04, current `base-os`, and role-appropriate current
  install evidence. The only start-allowed unit is `systemd-timesyncd`.
  `scylla-server`, `scylla-manager`, `scylla-manager-agent`, and
  `scylla-node-exporter` stay masked or disabled/inactive; this slice never
  unmasks or starts them. Monitoring stack/target scopes have an empty unit
  set and report stack/exporter starts as not-performed. Topology mutation is
  forbidden.
- `ansible/playbooks/scylla-cluster-shutdown.yml` — implemented fail-closed
  full-cluster guest-service shutdown validation before infrastructure
  teardown. It requires current full-cluster `scylla-health`,
  observation/inventory/trust, and narrow authorization bound to cluster,
  operation, topology, and health digests. PLAN-cited 2026.2 administrator
  pages do not publish a reviewed drain-then-stop order, so this slice
  inspects `scylla-server` only and refuses `nodetool drain`, systemd
  stop/mask, decommission, removenode, Terraform, VM destroy, and storage
  wipe. Manager quiesce is a separate prior playbook; while Manager remains
  unstarted, explicit not-applicable/not-performed authorization is required
  rather than inventing `sctool suspend`. Check mode is refused. Strict
  `deploy-scylla-vms.ansible-scylla-cluster-shutdown/v1` results hash Host
  IDs, report per-node drain/stop/mask as not-performed, keep the mutation
  boundary at not-started, and retain explicit not-performed items plus
  redacted blockers.
- `ansible/playbooks/os-upgrade-preflight.yml` — implemented role-aware,
  exact-one-target, serial-one, check-mode-safe read-only compatibility report.
  It requires current observation/inventory/trust, `base-os`, and exact
  role-appropriate package/configuration/service/health/route/availability
  evidence. Scylla also requires current storage, install/configure, complete
  cross-view health, and explicit replication/quorum/capacity/backup/topology
  rolling gates. The host checks only `/run/reboot-required`, argv-form
  `dpkg --audit`, fixed package-lock inodes through `/proc/locks`, Linux/
  architecture facts, and caller-policy-bound root/boot free space. Because
  PLAN has no approved target transition beyond the current Ubuntu 24.04
  baseline, no exact kernel policy, and no read-only proof of current APT
  metadata/repository compatibility, same-release requests are undefined,
  every other target is unsupported, and selected path remains not-performed.
- `ansible/playbooks/os-upgrade-in-place.yml` — implemented fail-closed
  exact-one-target, serial-one, check-mode-refused sensitive validation. It
  regenerates the current `os-upgrade-preflight` bindings from exact
  observation/inventory/trust/`base-os` and role package/configuration/storage/
  health evidence, requires an execution-successful and explicitly
  rolling-eligible preflight plus narrow operation/node/current-target-OS/
  architecture/evidence authorization, and refuses stale or failed evidence.
  Same-version requests are not upgrades; unsupported current/target OS and
  architecture mismatch are rejected. Because no in-place target transition,
  package sequence, role-safe shutdown, or reboot sequence is approved, strict
  `deploy-scylla-vms.ansible-os-upgrade-in-place/v1` results remain `blocked`,
  keep the mutation boundary at `not-started`, report package/source/service/
  reboot/kernel/configuration and automatic retry as `not-performed`, and set
  recovery-required false. Every result includes
  `target-transition-unapproved`; Scylla targets also include
  `shutdown-sequence-unreviewed`. The source runs no package, service, reboot,
  configuration, storage, Terraform, VM, or cloud mutation. Its source
  availability means the refusal contract is packaged and executable, not that
  an OS upgrade path is authorized.
- `ansible/playbooks/os-reprovision-prepare.yml` — implemented fail-closed,
  exact-one-target, serial-one destructive preparation validation for a
  future Python/Terraform-controlled immutable host replacement. It consumes
  immutable intent and caller-supplied provider/image facts but never contacts
  OCI, drains/quiesces a host, runs Terraform, or creates/destroys a VM.
- `ansible/playbooks/os-upgrade-postcheck.yml` — implemented fail-closed,
  read-only, check-mode-safe, exact-one-target verification of source-operation,
  OS, reboot, package, kernel, service, route, storage, and role-health evidence.
  Current validation-only in-place/reprovision sources always produce
  `source-upgrade-not-performed`, so no host can advance.

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

**Implemented production preflight slice (26.9.1):**

- `inventory-preflight` runs controller-side in forced check mode with no fact
  gathering, privilege escalation, or host connection. It compares current
  machine-validated inventory with service-generated typed expectations for
  exact stable IDs, roles, zones, provider IDs, Scylla datacenter/rack
  nullability, observation and inventory generations/digests, and the validated
  operation target set. Secret-like or extra inventory data is rejected at the
  strict inventory-machine boundary before execution.
- `connectivity-check` uses only `ansible.builtin.assert` and
  `ansible.builtin.ping`, with check mode, no fact gathering or privilege
  escalation, batches of five, and non-fatal per-host scheduling so all
  explicitly limited hosts can report. Python accepts only Ansible's success,
  host-failure, and unreachable exit codes for this playbook and strictly parses
  the redacted `PLAY RECAP` into complete, partial-failure, or failure evidence.
  Current inventory, complete trust, deterministic routes, and stable-ID limits
  remain mandatory; host-key checking is never relaxed.
- The canonical v1 inventory file is static JSON-compatible YAML accepted by
  Ansible. Its strict persisted form is normalized separately to the exact
  `ansible-inventory --list` evidence shape for parity checking.

**Implemented production base-OS slice (26.9.1):**

- The exact initial matrix is Ubuntu 24.04 with OCI `amd64` mapped to guest
  `x86_64`, or OCI `aarch64` mapped to guest `aarch64`. New desired state
  refuses all other image filters, including the former Oracle Linux values;
  persisted Oracle desired state is not silently migrated. There is no image,
  OS, version, or architecture default.
- `base-os` applies only the minimal package/time behavior documented in its
  catalog entry, supports check/diff preview, never reboots, and emits a strict
  address-free and module-output-free result. All other application and OS
  tuning remains assigned to later reviewed playbooks.

### Implemented jump-host SSH hardening contract

- `jump-host-configure` is jump-only, exact-one-target, serial-one, fatal, and
  mutating. Python authorizes one current jump stable ID against fresh
  observation, inventory, complete trust, valid routes, and successful Ubuntu
  `base-os` evidence with no reboot required. Non-jump IDs, extra hosts, stale
  provenance, and unrepresentable PermitOpen routes fail closed.
- The wrapper-owned drop-in is exactly
  `/etc/ssh/sshd_config.d/00-deploy-scylla-vms.conf`. Required policy is
  password/KbdInteractive/ChallengeResponse `no`, `PermitRootLogin no`,
  `PubkeyAuthentication yes`, `AuthenticationMethods publickey`,
  `AllowAgentForwarding`/`X11Forwarding`/`PermitTunnel`/
  `AllowStreamLocalForwarding no`, `AllowTcpForwarding local`, `GatewayPorts no`,
  `PermitListen none`, `PermitOpen` from exact inventory-derived RFC 1918
  private host:22 routes or `none`, `AllowUsers` from inventory `ansible_user`,
  and `LogLevel VERBOSE`. Host-key bypass, password/root login, agent/X11/
  tunnel/stream-local forwarding, remote/all TCP forwarding, and `PermitOpen any`
  are refused.
- The custom module validates the host-key algorithm/fingerprint with argv-form
  `ssh-keygen -l`, installs the drop-in atomically, runs argv-form `sshd -t`,
  and restores the previous valid file on validation failure. Reload uses the
  Ubuntu `ssh` systemd unit only after a successful change. Check mode does not
  predict live sshd behavior.
- Strict `deploy-scylla-vms.ansible-jump-host-configure/v1` evidence reports
  changed/noop/not-predicted/failed status, config/route/host-key/provenance
  digests, validation/reload truth, and bounded blockers. No addresses, raw
  sshd output, or configuration text are retained. No public operation invokes
  this source yet; live use remains gated by deploy/host-scope orchestration
  after jump `base-os`.

### Implemented Manager 3.12 agent install contract

- Official current Manager 3.12 is the selected agent release line because the
  stable [compatibility matrix](https://manager.docs.scylladb.com/stable/compatibility-matrix.html)
  lists it for ScyllaDB 2026.2 and the current
  [agent install](https://manager.docs.scylladb.com/stable/install-scylla-manager-agent.html)
  pages publish the 3.12 Ubuntu repository.
- The only package is `scylla-manager-agent`. Callers must supply one exact
  `3.12.*~0.YYYYMMDD.<hash>` Debian version; `latest`, ranges, 3.11, and
  hyphenated filename variants are refused.
- The wrapper reuses the vendored 2026 public key. Official install pages still
  mention short key ID `A43E06657BAC99E3`, but the official Manager 3.12
  Ubuntu `InRelease` is signed by
  `6C6ECC84F42AF147BD2A65AEC503C686B007F39E`. Hosts perform no key download.
- This slice does not write `/etc/scylla-manager-agent/scylla-manager-agent.yaml`,
  does not persist `DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN`, does not run
  `scyllamgr_agent_setup`, and does not start the agent or Scylla. Default HTTPS
  port `10001` is recorded only as documented metadata.
- Strict `deploy-scylla-vms.ansible-manager-agent/v1` evidence reports
  installed/no-change/not-predicted/failed status, the exact package version,
  repository/key digests, disabled/inactive service truth, and explicit
  `configuration_performed=false`, `auth_token_configured=false`,
  `helper_slice_configured=false`, and `server_reachability=not-performed`.
- No real host or package installation has been performed. No public operation
  invokes this source yet.

### Implemented Manager 3.12 server install contract

- Official current Manager 3.12 is the selected server release line because the
  stable [compatibility matrix](https://manager.docs.scylladb.com/stable/compatibility-matrix.html)
  lists it for ScyllaDB 2026.2 and the current
  [Manager install](https://manager.docs.scylladb.com/stable/install-scylla-manager.html)
  pages publish the 3.12 Ubuntu repository and package names.
- The official packages are `scylla-manager-server` and
  `scylla-manager-client`. Callers must supply one exact
  `3.12.*~0.YYYYMMDD.<hash>` Debian version applied to both; `latest`, ranges,
  3.11, and hyphenated filename variants are refused. The documented systemd
  unit is `scylla-manager.service`.
- Official pages install those packages first, then optionally configure a
  local Scylla backend or remote CQL cluster, run `scyllamgr_setup`, and
  `systemctl start scylla-manager.service`. Package install does not require a
  backend. This slice therefore remains install-only rather than inventing
  Manager storage or a registration token.
- The wrapper reuses the vendored 2026 public key. Official install pages still
  mention short key ID `A43E06657BAC99E3` and a keyserver import, but the
  official Manager 3.12 Ubuntu `InRelease` is signed by
  `6C6ECC84F42AF147BD2A65AEC503C686B007F39E`. Hosts perform no key download.
- This slice does not write `/etc/scylla-manager/scylla-manager.yaml`, does not
  persist `DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN`, does not run
  `scyllamgr_setup`, does not install a local Scylla backend, and does not
  start Manager.
- Strict `deploy-scylla-vms.ansible-manager-server/v1` evidence reports
  installed/no-change/not-predicted/failed status, the exact package versions,
  repository/key digests, masked/inactive service truth, and explicit
  `backend_configured=false`, `registration_performed=false`,
  `setup_performed=false`, and `service_started=false`.
- No real host or package installation has been performed. No public operation
  invokes this source yet.

### Implemented Manager local-backend preflight contract

- The selected backend mode is versioned
  `deploy-scylla-vms.manager-backend-local-one-node-policy/v1`:
  the official recommended local one-node ScyllaDB backend shares the Manager
  VM, is never the managed Scylla data cluster, permits no CQL network ingress,
  and will use loopback-only contact with the documented default CQL port
  `9042`. The compatibility target is ScyllaDB 2026.2. Loopback v1 uses no
  backend credentials or TLS secrets; future Manager-agent tokens remain
  environment-only protected inputs.
- The selection follows the official
  [Manager installation guide](https://manager.docs.scylladb.com/stable/install-scylla-manager.html)
  and
  [Manager database configuration reference](https://manager.docs.scylladb.com/stable/config/scylla-manager-config.html).
  It is also bound to immutable Manager v3.12.0
  [`scylla-manager.yaml`](https://github.com/scylladb/scylla-manager/blob/v3.12.0/dist/etc/scylla-manager.yaml)
  and
  [`scyllamgr_setup`](https://github.com/scylladb/scylla-manager/blob/v3.12.0/dist/scripts/scyllamgr_setup)
  source. Automatic keyspace creation at Manager start and the documented
  manual-replication recommendation are design evidence, not authorization to
  start Manager or create schema.
- Only the prior typed `backend-mode` planning blocker is resolved. Package
  availability, storage and capacity policy, tuning, setup behavior,
  configuration ownership/mode, schema/keyspace policy, recovery, and the
  mutating configuration source remain explicit unknown or blocked gates.
  Manager stays masked/inactive, and this slice does not install, configure,
  tune, or start local Scylla.
- `manager-backend-preflight` is source-available, read-only, Manager-only,
  exact-one-target, serial-one, fatal, and check-mode-safe. Python requires
  exact current Ubuntu 24.04/architecture/base-OS and Manager 3.12 install
  evidence, the immutable activation/backend plan, and current inventory,
  trust, readiness, and packaged-source provenance before execution.
- Host inspection is bounded to OS/architecture, CPU/memory/root capacity,
  approved-mount counts, fixed local Scylla and Manager package/service states,
  reboot requirement, and loopback-interface availability. It performs no
  environment or process-command collection, repository query, configuration
  content read, raw-device collection, metadata/cloud access, network
  connection, CQL/schema operation, package mutation, configuration write, or
  service mutation.
- Strict
  `deploy-scylla-vms.ansible-manager-backend-preflight/v1` evidence retains
  only the Manager stable ID, role, bounded capacities/counts, status enums,
  policy/provenance digests, explicit not-performed actions, and bounded
  blockers. It omits addresses, provider IDs, raw paths, package output,
  commands, configuration, credentials, and secrets. `evidence-ready` means
  only that bounded host facts can inform a later reviewed installation plan;
  backend operational readiness remains `not-performed`.
- No deploy authorization, execution owner, reconciliation, journal
  transition, CLI/public wiring, real Ansible execution, or live system access
  is implemented. The next stage is an operation-bound preflight execution and
  reconciliation owner, followed by separately reviewed package/storage/
  tuning/capacity and local-backend installation planning.

### Implemented Manager local-backend storage discovery contract

- The operation-bound storage allocation/discovery planner accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  held deploy lock. It revalidates the full immutable chain through exact
  post-package reconciliation, backend policy and installation plans, current
  Manager package evidence, desired/Terraform input/observation/inventory/
  trust/readiness, source/catalog, and unchanged VERIFY journal.
- It persists independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-allocation-context/v1`
  then
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-allocation-plan/v1`
  companions. Both are built in memory; an exact context-only prefix may
  recover and exact complete records are reused without writes. The existing
  post-package reconciliation and installation plans are never rewritten.
- Allocation is limited to one dedicated Manager-role OCI Block Volume whose
  stable/provider identity and attachment exactly match desired state,
  Terraform input, the observed storage manifest, inventory, and readiness.
  Root/boot storage, local NVMe, arbitrary attachments, path/order selection,
  generic free space, and Scylla-role storage are forbidden. Missing,
  ambiguous, or path-only identity creates no executable discovery scope.
- The plan can retain only bounded requested/observed GiB, count/backend
  states, and redacted identity/manifest/provenance digests. It keeps capacity
  policy `unknown` and adequacy `not-evaluated`; exact allocation identity is
  not a capacity-sufficiency claim. Only an exact allocation with a non-path
  guest identity and current packaged source may expose one read-only Manager
  discovery target.
- `manager-backend-storage-discover` is a distinct source-available,
  Manager-only, exact-one-target, serial-one, fatal, check-mode-safe contract.
  It correlates bounded Linux block/mount/signature/holder/ownership/topology
  facts to the exact Terraform manifest and returns strict
  `deploy-scylla-vms.ansible-manager-backend-storage-discovery/v1` evidence.
  Results retain only the stable ID, bounded count/size/type/signature/
  ownership/status enums, blockers, and hashed device/topology/manifest/
  provenance digests. Raw paths, serials, UUIDs, addresses, provider IDs,
  commands, variables, output, environment, credentials, and secrets are
  forbidden.
- The source never writes or wipes devices, partitions, creates RAID or
  filesystems, mounts, edits fstab, configures or starts services, or accesses
  CQL.
- The operation-bound execution owner accepts only canonical identity, the
  matching held deploy lock, the controlled runner, and the exact validated
  sibling Ansible executables/toolchain. It reconstructs the one Manager
  target, manifest-bound variables, hash-checked source, and anchored command;
  records durable `started`; and persists generation-guarded
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-execution/v1`
  plus immutable-prefix
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-evidence/v1`.
  Started uncertainty, process failure, malformed semantics, drift, or
  post-call persistence failure is permanent manual-recovery/no-retry. Exact
  completion re-entry performs no process call or write.
- The subprocess-free immutable reconciliation binds allocation, execution,
  and evidence under
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-reconciliation/v1`.
  It marks only strict discovered evidence succeeded and keeps bounded blocked
  evidence blocked. Capacity adequacy remains `unknown`; storage preflight and
  preparation remain unavailable/not-started; wipe safety is `not-evaluated`;
  and owned-noop is `not-inferred`. It leaves the VERIFY journal and all prior
  records unchanged and performs no authorization, mutation, storage
  preflight/preparation, configuration/service work, CLI/public wiring, live
  Ansible, or real-system access. The following independently versioned stage
  implements the separately reviewed Manager-backend storage-preflight
  planning boundary.

### Implemented Manager local-backend storage preflight contract

- The immutable planning owner accepts only canonical state-root/cluster
  identity, one operation UUID, and the matching held deploy lock. It
  revalidates the exact local-one-node backend, host preflight, package,
  allocation, successful storage-discovery reconciliation, Manager target,
  desired/Terraform manifest, hashed guest-device evidence, source/catalog,
  and unchanged VERIFY-journal chain.
- It persists independently versioned owner-only
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-context/v1`
  and
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-plan/v1`
  records. Exact records are reused without writes and an exact context-only
  prefix may recover; callers cannot supply a device, path, action, layout,
  capacity decision, command, variable, target, or free text.
- The approved policy is one dedicated Manager Block Volume, one whole device,
  XFS, fixed `/var/lib/scylla` ownership boundary, required fstab/mount intent,
  and a Manager-local one-node role marker. RAID, partitions, local NVMe,
  root/boot fallback, arbitrary attachments, and shared Scylla-role storage
  remain forbidden.
- Requested, Terraform-observed, and discovered device GiB/count/type plus
  manifest/device identity must match exactly. This proves only
  operator-selected allocation conformance; long-term operational capacity
  sufficiency remains explicitly `not-proven` and operator-policy-bound.
- `manager-backend-storage-preflight` is a distinct source-available,
  read-only, Manager-only, exact-one-target, serial-one, fatal, and
  check-mode-safe contract. It reconciles the exact desired policy, Terraform
  manifest, discovery evidence, and current bounded host facts and classifies
  only `owned-noop`, `prepare-required`, or `blocked`.
- A blank exact unowned device may be `prepare-required` without wipe. A
  signature on an otherwise unowned device is foreign, blocks preparation,
  and reports wipe-required separately for a future reviewed ownership and
  consent boundary. Foreign ownership, unexpected mount/fstab/marker state,
  root/boot ancestry, holders, partitions, ambiguity, or identity/size/
  topology mismatch also block. Absence alone never proves wipe safety.
- Strict
  `deploy-scylla-vms.ansible-manager-backend-storage-preflight/v1` results
  retain only stable ID, bounded backend/layout/capacity/disposition/action
  values, booleans, counts, blockers, and hashed device-set/preparation-intent/
  provenance digests. Raw paths, serials, UUIDs, addresses, provider IDs,
  commands, variables, output, environment, credentials, and secrets are
  absent.
- The operation-bound owner accepts only canonical identity, the matching held
  deploy lock, controlled runner, and exact validated sibling Ansible
  executables/toolchain. It revalidates the complete planning and discovery
  chain, derives the exact target/policy/manifest/discovery projection,
  hash-checked source, variables, and anchored command, and durably records
  `started` before its sole read-only call. It persists generation-guarded
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-execution/v1`
  and immutable-prefix
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-evidence/v1`
  records.
- Started uncertainty, process/output failure, malformed or semantically
  conflicting results, drift, and post-call persistence failure are permanent
  manual-recovery/no-retry. Exact completed re-entry is zero-process and
  zero-write.
- Immutable
  `deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-reconciliation/v1`
  marks exact preflight evidence succeeded. `owned-noop` is not required and
  never authorized; blocked results stay blocked; only `prepare-required`
  derives a stable-ID/disposition/device-set/preparation-intent scope, with
  wipe-required targets and scope digest kept separately. Capacity sufficiency
  remains `not-proven`, but does not block exact allocation preparation or
  satisfy any later service-health/capacity gate. Exact `prepare-required`
  scope is now `evidence-ready-authorization-required`; source state is
  available while operation authorization and execution remain unavailable.
- The narrow `manager-backend-storage-prepare` source implements only the
  reviewed single-device XFS/fstab/mount/ownership-marker boundary described
  in the catalog. It revalidates immediately before its first irreversible
  step, keeps wipe consent separate and digest-bound, and emits only the strict
  redacted result contract. Adding the source changes the packaged source/
  catalog provenance, so an older immutable plan fails closed and requires a
  new operation rather than being rewritten.
- The planning/reconciliation boundary performs no authorization, storage
  mutation, preparation execution,
  postcheck, configuration/service work, journal transition, CLI/public
  wiring, live-system access, or real Ansible execution.

### Implemented Scylla 2026.2 monitoring-agent install contract

- Official Scylla Monitoring scrapes `node_exporter` on each Scylla server and
  the current [administration guide](https://docs.scylladb.com/manual/stable/operating-scylla/admin.html)
  documents optional port `9100`. The official Linux package set includes
  `scylla-node-exporter` from the signed ScyllaDB 2026.2 Ubuntu repository.
- The only package is `scylla-node-exporter`. Callers must supply the exact
  current `scylla-install` 2026.2 Debian version; `latest`, ranges, 2026.1, and
  Manager-style tilde versions are refused. Jump, Manager, and monitoring hosts
  are refused.
- Official process-exporter is not documented as a per-node Ubuntu package for
  this baseline, so it is not installed. The helper `node_exporter_install`
  script is refused because it downloads binaries.
- This slice does not write `/etc/default/scylla-node-exporter` or
  `/etc/sysconfig/scylla-node-exporter`, does not start the unit, and does not
  bind `9100`. Startup would require an unreviewed listen-address decision;
  listen policy remains `not-started`.
- Strict `deploy-scylla-vms.ansible-monitoring-agent/v1` evidence reports
  installed/no-change/not-predicted/failed status, the exact package version,
  repository/key digests, disabled/inactive service truth, `listen_policy`, and
  explicit false values for configuration, process-exporter, stack, targets,
  Manager registration, Scylla startup, and secrets.
- No real host or package installation has been performed. No public operation
  invokes this source yet.

### Implemented Scylla Monitoring 4.16.0 stack install contract

- Official Scylla Monitoring must run on a dedicated server, currently
  documented as [installing the 4.16.0 archive](https://monitoring.docs.scylladb.com/stable/install/monitoring-stack.html)
  from `https://github.com/scylladb/scylla-monitoring/archive/4.16.0.tar.gz`.
  GitHub release `4.16.0` is commit `fac61b89b229a69d2af2d88b7e09a6316c3924e4`.
  The tagged `versions.sh` lists ScyllaDB 2026.2 among supported dashboard
  versions and pins Prometheus `v3.14.0`, Grafana `13.2.0`, Alertmanager
  `v0.34.0`, Loki `3.7.7`, and Promtail `3.6.11`.
- The only installed artifact is that exact archive after SHA-256 digest
  check. Callers must supply `4.16.0`; `latest`, ranges, 4.15, and 4.16.1 are
  refused. Jump, Manager, and Scylla data nodes are refused.
- Official startup uses `start-all.sh` or Docker Compose, publishes Grafana
  `3000`, Prometheus `9090`, and Alertmanager `9093`, and uses anonymous
  Grafana admin with a default admin password. Docker CE/Ubuntu `docker.io`
  versions are not pinned by the archive, and container images are not
  Scylla-signed. This slice therefore does not install Docker, pull images,
  generate Compose/`.env`, write Grafana auth, or start containers; listen
  policy remains `not-started`.
- This slice does not generate `prometheus/scylla_servers.yml` or Manager
  target files, does not install `scylla-node-exporter`, and does not register
  Manager or start Scylla.
- Strict `deploy-scylla-vms.ansible-monitoring-stack/v1` evidence reports
  installed/no-change/not-predicted/failed status, the exact stack and
  component versions, archive digest and source commit, docker
  disabled/inactive truth, `listen_policy`, documented ports, and explicit
  false values for targets, auth, public bind, Compose, containers, Manager
  registration, Scylla startup, and secrets.
- No real host or archive installation has been performed. No public operation
  invokes this source yet.

### Implemented Scylla Monitoring 4.16.0 target-file contract

- Official 4.16.0 file-SD is documented by the
  [install guide](https://monitoring.docs.scylladb.com/branch-4.16/install/monitoring-stack.html)
  and the tagged `prometheus/scylla_servers.example.yml`,
  `prometheus/scylla_manager_servers.example.yml`,
  `prometheus/prometheus.yml.template`, and `start-all.sh`. Scylla targets are
  IPs without default ports plus `cluster`/`dc` labels; Prometheus relabel
  adds Scylla `9180`, node_exporter `9100`, and manager_agent `5090`. Manager
  servers are `host:5090` and the Manager file is required. Default startup
  reuses the Scylla file for node_exporter and manager_agent; `--target-directory`
  expects those names explicitly.
- This slice writes those four files under
  `/opt/scylla-monitoring/4.16.0/prometheus/` from current inventory RFC 1918
  private addresses. Jump, monitoring, and public addresses are refused. PLAN
  does not require live `monitoring-agent` evidence for file generation;
  hashed Scylla identities bind the reused agent/exporter files.
- Callers must supply current Ubuntu 24.04 `base-os` without reboot and current
  successful `monitoring-stack` 4.16.0 evidence on the exact monitoring stable
  ID. Jump, Manager, and Scylla data nodes are refused.
- This slice does not run `start-all.sh`, `genconfig.py`, Docker, Compose, or
  live scrape. Listen policy remains `not-started`. Scrape-readiness remains
  `not-performed` because exporters and UI ports stay unstarted.
- Strict `deploy-scylla-vms.ansible-monitoring-targets/v1` evidence reports
  generated/no-change/not-predicted/failed status, official file paths and
  content digests, target counts by role, hashed identities, stack/agent-target/
  inventory provenance, documented scrape ports, listen policy, scrape
  readiness, and explicit false values for scrape, exporter/stack/container
  startup, public bind, auth, Compose, Manager registration, Scylla startup,
  and secrets.
- No real host or target-file write has been performed. No public operation
  invokes this source yet.

### Implemented Manager 3.12 task validation contract

- Official Manager 3.12 task APIs are documented by the
  [task list](https://manager.docs.scylladb.com/branch-3.12/sctool/task.html),
  [suspend and resume](https://manager.docs.scylladb.com/branch-3.12/sctool/suspend-resume.html),
  [repair](https://manager.docs.scylladb.com/branch-3.12/repair/index.html), and
  [backup](https://manager.docs.scylladb.com/branch-3.12/backup/index.html)
  pages. Inspect uses `sctool tasks`; quiesce uses
  `sctool suspend --cluster <id|name>`; resume uses
  `sctool resume --cluster <id|name>`. Repair and backup creation use
  `sctool repair` and `sctool backup`. Those commands talk to the Manager API,
  defaulting to `http://127.0.0.1:5080/api/v1` or a URL derived from
  `/etc/scylla-manager/scylla-manager.yaml`, and require a registered
  cluster. Cluster add automatically schedules a weekly repair; backup tasks
  require an explicit storage location.
- The current `manager-server` slice is install-only: `scylla-manager.service`
  remains masked and inactive, no backend is configured, no cluster is
  registered, and no auth token is written. PLAN also does not define desired
  backup locations, cron, retention, or repair intensity. A live task-create
  or sctool path would invent those later slices.
- This slice therefore remains validation-only. Callers must supply one
  manager stable ID, exact Ubuntu 24.04 image evidence, successful current
  `base-os` without reboot, and successful current `manager-server` evidence
  that is still masked/inactive and unregistered. Jump, Scylla, and monitoring
  hosts are refused. The only actions are `inspect`, `quiesce`, `resume`, and
  `validate`; the default is `inspect`.
- The playbook inspects only argv-form `systemctl is-enabled` and
  `systemctl is-active` for `scylla-manager.service`. It does not start or
  unmask Manager, write `scylla-manager.yaml`, persist
  `DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN`, register a cluster, start Scylla, or
  invoke sctool. An unmasked or active unit fails closed because no reviewed
  live API path exists.
- Strict `deploy-scylla-vms.ansible-manager-tasks/v1` evidence reports
  not-performed/not-predicted/failed status, the requested action and
  backup/repair kinds, `applied=false`, masked/inactive service truth,
  explicit false backend/registration/setup/startup/token/sctool flags, the
  official not-performed command set, provenance digests, and exact blockers
  `backend-unconfigured`, `manager-inactive`, and `manager-unregistered` on
  the expected inactive path.
- No real host or Manager API call has been performed. No public operation
  invokes this source yet.

**Implemented production storage-preparation slice (26.9.1):**

- Python re-runs complete storage reconciliation before creating the private
  runtime payload and rejects stale/tampered preflight, mismatched targets,
  digests, classifications, or approvals before Ansible execution.
- The role uses fixed argv commands only: read-only `lsblk`, `wipefs`, and
  `findmnt`; separately approved `wipefs --all --force`; exact-set
  `mdadm --create --run --level=0`; `mkfs.xfs -f -L scylla-data`; UUID-only
  `blkid`; and mount of the fixed canonical Scylla path. It does not select by
  glob or enumeration order and accepts no user command fragments.
- `deploy-scylla-vms.ansible-storage-prepare/v1` reports only changed, no-op,
  not-predicted, or failed status; backend/layout; hashed device set and
  filesystem/marker identities; completed steps; irreversible-step status; and
  bounded verification. A write failure after the first destructive command is
  explicitly non-rollbackable and requires manual recovery followed by full
  rediscovery and preflight before retry.
- This source has static/fake tests only and has not been exercised on real
  devices. No CLI operation orchestrates or invokes it yet; live use remains
  gated by operation confirmation, journaling, and verification wiring.

**Implemented production storage-postcheck slice (26.9.1):**

- Python revalidates current lock/readiness/inventory and exact discovery,
  preflight, preparation, desired-policy, and Terraform-manifest provenance
  before constructing the owner-only postcheck expectation for one Scylla ID.
- The role uses only fixed read-only metadata commands and bounded reads of the
  canonical fstab, mount, and ownership marker. It reports remediation
  requirement on failure and never repairs, remounts, opens a raw device for
  writes, or changes host state.
- A passing postcheck is mandatory but insufficient input to the implemented
  package-only `scylla-install` slice.

### Implemented production storage-retire contract

- Python revalidates current lock/readiness/inventory plus exact discovery,
  owned-noop preflight, preparation, postcheck, desired-policy, and
  Terraform-manifest provenance before constructing the owner-only retire
  payload for one Scylla stable ID.
- Authorization is bound to the operation, node, device-set digest, and
  `retain`/`delete`/`ephemeral` disposition. Membership absence is required.
  `delete` requires separately bound wipe consent; retain and ephemeral refuse
  wipe acknowledgement. Blocked storage is never executable.
- The role uses only fixed argv commands: read-only `lsblk`, `findmnt`,
  `wipefs`, and `systemctl is-active scylla-server`; `umount` of the canonical
  Scylla mount; UUID fstab removal; exact `mdadm --stop /dev/md/scylla-data`
  for RAID0; and separately approved `wipefs --all --force` only for delete.
  It never selects by `/dev/nvme*` order and does not start or stop Scylla.
- `deploy-scylla-vms.ansible-storage-retire/v1` reports only
  changed/no-op/not-predicted/failed status, hashed devices, disposition,
  first irreversible step, completed steps, manual-recovery requirement,
  explicit not-performed Terraform/VM/wipe items, provenance digests, and
  redacted blockers. A write failure after the first destructive command
  requires manual recovery followed by rediscovery before retry.
- This source has static/fake tests only and has not been exercised on real
  devices. No CLI operation orchestrates or invokes it yet.

### Implemented production service-converge contract

- Python requires exact Ubuntu 24.04 image evidence, successful current
  `base-os` without reboot, complete observation/inventory/trust bindings, and
  one stable-ID limit. Role-appropriate current install evidence is required
  except for the generic `base` scope: `jump-host-configure`, `scylla-install`,
  `manager-agent`, `manager-server`, `monitoring-agent`, `monitoring-stack`, or
  `monitoring-targets`.
- The typed allowlist is the PLAN-owned unit set only. `systemd-timesyncd` may
  be enabled/started, and `restart_policy=always` may restart only that unit.
  `scylla-server` remains masked/inactive, `scylla-manager` remains
  masked/inactive, and `scylla-manager-agent` / `scylla-node-exporter` remain
  disabled/inactive. PLAN does not define a reviewed start path for already
  bootstrapped Scylla, Manager, exporters, or the monitoring stack, so those
  starts stay not-performed.
- Check mode is preview-only and reports `not-predicted`. Success requires
  already-correct inactive/masked states or a timesyncd enable/start. An
  unexpected active or unmasked forbidden unit fails closed without stop,
  unmask, start, package install, config rewrite, firewall, SSH, or Terraform.
- Strict `deploy-scylla-vms.ansible-service-converge/v1` evidence reports
  converged/no-change/not-predicted/failed status, per-unit
  desired/observed/enabled/active flags, applied/started/restarted truth,
  provenance digests, explicit not-performed starts, and redacted blockers.
  No public operation invokes this source yet.

### Implemented production scylla-cluster-shutdown contract

- This slice is sensitive/destructive guest shutdown validation, not Terraform
  destroy. Python requires the exact complete Scylla stable-ID set, current
  full-cluster `scylla-health`, complete observation/inventory/trust bindings,
  and narrow authorization bound to cluster, operation, topology, health, and
  Manager-task digests.
- PLAN destroy runs `manager-tasks` quiesce as a separate prior playbook. The
  current Manager 3.12 slice remains validation-only because `scylla-manager`
  is masked, inactive, and unregistered. This source therefore requires
  explicit authorization that Manager tasks are not-applicable/not-performed
  rather than inventing `sctool suspend`.
- The PLAN-cited [administrator procedures index](https://docs.scylladb.com/manual/stable/operating-scylla/)
  and [administration guide](https://docs.scylladb.com/manual/stable/operating-scylla/admin.html)
  do not publish a reviewed 2026.2 whole-cluster `nodetool drain` then systemd
  stop/mask order. The playbook inspects only argv-form `systemctl is-enabled`
  and `is-active` for `scylla-server.service`. It never drains, stops, masks,
  starts, decommissions, runs `removenode`, wipes storage, or invokes Terraform.
- Serial-one and fatal. Check mode is refused. The first inspect failure stops
  the sequence; started mutation cannot occur and is never retried.
- Strict `deploy-scylla-vms.ansible-scylla-cluster-shutdown/v1` evidence reports
  not-performed/not-predicted/failed status, hashed Host IDs, per-node
  drain/stop/mask states, observed enablement/activity, mutation boundary
  `not-started`, provenance digests, explicit not-performed drain/stop/mask/
  Terraform/VM/wipe/decommission/start items, and redacted blockers
  `manager-tasks-not-applicable` and `official-command-order-unreviewed`.
  No public operation invokes this source yet.

### Implemented production os-upgrade-preflight contract

- Python requires one exact role-aware stable-ID limit, serial-one scheduling,
  exact current Ubuntu 24.04 image/architecture evidence, complete current
  observation/inventory/trust and `base-os`, a UUID operation intent, exact
  strategy constraints, `max_unavailable=1`, no competing operation, and
  digest-bound free-space policy. Provider image facts are optional only for
  `auto`, required for `reprovision`, forbidden for `in-place`, validated
  offline, and never discovered from OCI by this slice.
- Jump targets require current `jump-host-configure`; Manager targets require
  current install-only `manager-server`; monitoring targets require current
  install-only `monitoring-stack` plus `monitoring-targets`. The latter two
  remain blocked because their documented service/health/configuration
  prerequisites are not implemented or started.
- Scylla targets require current exact-2026.2 `scylla-install`,
  `scylla-configure`, storage-postcheck readiness, and complete all-node
  cross-view UN health with active service, CQL/API reachability, schema
  agreement, idle streaming, and current provenance. Independently supplied
  replication, quorum, capacity, backup-policy, topology-work, shutdown, and
  drain gates are digest-bound to that health snapshot. Unknown or failed
  values make `rolling_eligible=false`; service state alone never authorizes
  upgrade.
- The custom module is read-only and check-mode-safe. It runs only fixed
  argv-form `/usr/bin/dpkg --audit`, checks `/run/reboot-required`, observes
  only the fixed APT/dpkg lock-file inodes in `/proc/locks`, validates Linux
  and guest architecture, and compares `statvfs` root/boot free bytes with
  caller-validated thresholds. It emits no PIDs, paths from inventory,
  package output, addresses, or environment.
- The official Ubuntu release-upgrade checklist requires a fully updated
  system, no pending reboot, sufficient free space, reviewed third-party
  repositories, backups, and a sequential approved release path. The reviewed
  sources publish no numeric free-space threshold, and the current PLAN
  selects no target after Ubuntu 24.04. ScyllaDB's rendered support table did
  not expose reliable support-cell values during bounded lookup. Therefore
  package currency, repository state, and exact kernel policy remain unknown;
  Ubuntu 24.04-to-24.04 is classified `undefined`, every other OS/version is
  `unsupported`, and neither in-place nor reprovision is selected.
- Strict `deploy-scylla-vms.ansible-os-upgrade-preflight/v1` evidence reports
  blocked/failed status, exact current/target transition classification,
  requested strategy, selected path `not-performed`, deterministic per-gate
  passed/failed/unknown/not-performed status, independent rolling eligibility,
  provenance digests, explicit not-performed actions, and bounded blockers.
  It never runs APT mutation, `do-release-upgrade`, reboot, service start/stop,
  desired-state mutation, OCI discovery, Terraform, or VM replacement. No
  public operation invokes this source yet.

### Implemented production os-reprovision-prepare contract

- This thirtieth source-available entry is destructive preparation
  validation, not reprovision execution. It is role-aware, exact-one-target,
  serial-one, fatal, and check-mode-refused. The packaged playbook only gathers
  current Ubuntu/architecture facts, validates controller-built immutable
  intent, and emits blocked evidence.
- Python regenerates the exact current `os-upgrade-preflight` controller
  projection from observation/inventory/trust/`base-os` and role package,
  configuration, storage, health, route, availability, and topology evidence.
  Stale, failed, or mismatched preflight is refused. Jump and Scylla targets
  additionally require its explicit rolling-eligibility truth; Manager and
  monitoring retain their current explicit service/health blockers so this
  slice can report the unimplemented replacement prerequisites without
  claiming readiness.
- The current provider/image facts and target image facts are caller-supplied,
  digest-bound offline evidence. They bind exact current and target OS/version/
  architecture plus hashed image and current provider identities. An
  `available` fact is not OCI discovery, capacity evidence, or proof that a
  future replacement identity exists. The stable logical ID is preserved, the
  replacement provider identity state remains `not-created`, and policy
  requires a distinct provider identity after replacement.
- Role safety evidence binds exact topology, lifecycle evidence, service/
  membership/availability/route status, and explicit `retain`, `delete`,
  `ephemeral`, or jump-only `none` storage disposition. Unknown is never a
  pass. Scylla accepts only completed reviewed live/dead removal evidence or an
  explicitly blocked `replace-node` delegation; generic Scylla reprovision
  remains forbidden. Manager and monitoring report unimplemented restore,
  Manager re-registration, and monitoring target refresh; every role reports
  replacement-host retrust and provider-identity revalidation requirements.
- Narrow authorization binds cluster UUID, operation UUID, stable ID, role,
  current provider digest, exact old/new image facts, OS/version/architecture,
  storage disposition, topology, preflight, role safety, observation,
  inventory, and trust. It authorizes validation only.
- PLAN still approves no target after Ubuntu 24.04 and no Python/Terraform
  replacement orchestration. Strict
  `deploy-scylla-vms.ansible-os-reprovision-prepare/v1` results therefore
  remain `blocked` with `target-transition-unapproved`,
  `terraform-replacement-orchestration-unimplemented`,
  `provider-identity-revalidation-required`, and `host-retrust-required`, plus
  role-specific blockers. Mutation boundary stays `not-started`;
  recovery-required is false; Terraform plan/apply/destroy, VM replacement/
  destroy, storage detach/delete/wipe, package mutation, desired-state/
  configuration changes, service start/stop, drain/decommission/removenode,
  restore/re-registration, monitoring target refresh, retrust, reboot,
  automatic retry, and provider discovery are explicitly `not-performed`.
  Results omit addresses, raw provider facts, device paths, secrets,
  environments, and command output. No public operation invokes this source.

### Implemented production os-upgrade-postcheck contract

- This thirty-first source-available production catalog entry is read-only,
  role-aware, exact-one-target, serial-one, fatal, and check-mode-safe.
- Python requires an exact source-operation result and matching authorization
  from either `os-upgrade-in-place/v1` or `os-reprovision-prepare/v1`. It binds
  cluster and operation UUIDs, stable ID, role, hashed current provider
  identity, exact previous/target/current OS version and architecture, source
  mode/schema/result digest, observation/inventory/trust generations and
  digests, and current `base-os`, package, configuration, storage, route,
  service, and role-health evidence.
- Validation-only source results are never upgrades. The current in-place and
  reprovision contracts prove `mutation_boundary=not-started`, `applied=false`,
  blocked/failed status, and every mutation action `not-performed`. The
  postcheck therefore always preserves the exact
  `source-upgrade-not-performed` blocker. Same-version requests also remain
  non-upgrades, and unsupported or PLAN-unapproved targets cannot verify.
- The custom module performs only bounded reads of `/etc/os-release`,
  architecture, kernel release, `/run/reboot-required`, argv-form
  `/usr/bin/dpkg --audit`, exact allowlisted package versions with
  `/usr/bin/dpkg-query`, and fixed allowlisted service state with
  `/usr/bin/systemctl is-enabled`/`is-active`. It consumes current strict
  controller evidence for route, configuration, storage, and role health.
  Scylla readiness requires the complete existing topology/schema/streaming/
  storage-health contract; process status alone never proves it.
- Strict `deploy-scylla-vms.ansible-os-upgrade-postcheck/v1` evidence reports
  blocked/failed status, source mode/schema/result digest, exact transition
  classification/comparison, deterministic per-gate status, performed and
  not-performed verification, current state digests, provenance digests,
  mutation/remediation/automatic-remediation false, and bounded redacted
  blockers. It omits addresses, provider output, raw package/command output,
  device paths, secrets, and environment.
- It never runs APT mutation, package changes, reboot, service changes,
  configuration or storage writes, trust replacement, OCI/Terraform calls,
  Scylla mutation, or remediation. Source availability means this truthful
  executable verifier/refusal is packaged; no supported source can currently
  supply completed-upgrade evidence, OS upgrade is not operational, and no
  public operation invokes this source.

**Packaged fail-closed Scylla installation slice (26.9.1):**

- The user-selected baseline is Ubuntu 24.04 with ScyllaDB release line 2026.2.
  Callers must supply one exact Debian package version; `latest`, ranges,
  prefixes, release candidates, and other release lines are refused.
- The upstream `scylladb/scylla-ansible-roles` dependency is pinned to commit
  `42592128ff0399be8ffa18dbc985c4b026e7abd0`, role
  `scylladb.scylla_node`. Installation does not invoke it because that snapshot
  uses `apt_key`, shell version discovery, OpenJDK 8, package removal, and broad
  repository handling on Debian/Ubuntu. The pin remains immutable provenance
  for the next constrained configuration slice.
- The wrapper vendors the documented 2026 public signing key with a pinned
  SHA-256 digest, uses its full fingerprint
  `6C6ECC84F42AF147BD2A65AEC503C686B007F39E`, configures only the official
  signed 2026.2 APT repository, and installs the exact official package set.
  Hosts perform no signing-key download. APT TLS/signature verification is
  never disabled.
- Exact cluster/spec/image/observation/inventory/trust/base-OS/storage digests,
  stable-ID scope, and service mask/inactive status are required and returned
  through `deploy-scylla-vms.ansible-scylla-install/v1`. No raw package output,
  addresses, provider IDs, credentials, or arbitrary blockers are retained.
- No real host or package installation has been performed.
- The full fingerprint is authenticated by the official 2026.2 `InRelease`
  signature and its matching HTTPS-hosted repository definition, with the
  documented 64-bit suffix independently present in immutable official ScyllaDB
  source. Immutable local provenance records retrieval, digest, complete
  primary/subkey fingerprints, UID, expiry, revocation inspection, and the
  verification procedure.

### Implemented Scylla 2026.2 configuration contract

- The pinned upstream role is not invoked: its behavior cannot be constrained to
  configuration-only semantics. Wrapper-owned templates contain exactly the
  reviewed `scylla.yaml` keys plus `dc`, `rack`, and `prefer_local=true`.
- The initial single-datacenter seed policy selects one deterministic stable ID.
  Growth can retain healthy persisted seeds and expands to at most three,
  preferring distinct racks. Add and replace policies require explicitly
  supplied healthy surviving members and exclude the joining/replacement target
  from being the sole seed.
- Configuration intent is bound to exact base-OS, storage-postcheck,
  Scylla-install, desired-spec, observation, inventory, and trust digests.
  Cluster name and datacenter/rack changes after successful initial
  configuration are refused.
- Strict `deploy-scylla-vms.ansible-scylla-configure/v1` evidence reports only
  changed/no-op/not-predicted/failed status, configuration/topology/seed
  digests, exact installed version, masked/inactive service evidence,
  prerequisite digests, bounded blockers, and
  `runtime_validation_performed=false`. It contains no raw configuration,
  addresses, secrets, provider IDs, or command output.
- No supported standalone full-configuration validator exists for this release,
  so this slice uses model, template, digest, permission, and static validation
  and does not run Scylla. Runtime cluster-wide health remains a separate
  future slice.

### Implemented Scylla 2026.2 bootstrap contract

- Python accepts no inferred bootstrap mode. `initial-seed` requires reviewed
  empty-cluster evidence, no live members/state, and the deterministic target
  as the exact sole seed. `join-existing` requires the target absent, healthy
  surviving members and seeds, capacity/topology/schema gates, a non-self-only
  seed policy, and an exact digest-bound add/scale intent.
- One target, package release, operation, node, desired specification,
  observation, inventory, trust, storage-postcheck, package-install,
  configuration, topology, seed policy, and authorization are bound before
  execution. The service must still be masked and inactive.
- The serial-one, fatal playbook gathers facts and revalidates package,
  configuration-file digests, mode evidence, and service state immediately
  before the first mutation. The first mutation is one systemd unmask/enable/
  start boundary; no shell command is used.
- Bounded local CQL readiness and argv-form `nodetool info`, `status`,
  `netstats`, and `describecluster` checks require active service, Up Normal,
  exact datacenter/rack, a self-consistent Host ID, completed streaming, and
  schema agreement. A timeout, join conflict, streaming activity, or schema
  disagreement stops the play.
- Strict `deploy-scylla-vms.ansible-scylla-bootstrap/v1` evidence contains only
  mode/status, target stable ID, service state, hashed ring/Host-ID evidence,
  datacenter/rack, streaming state, prerequisite digests, mutation boundary,
  recovery requirement, and bounded blockers. It contains no raw command
  output, address, provider ID, or secret.
- Failure never triggers automatic destruction or retry. A node is stopped and
  remasked only when post-failure evidence proves it never joined; otherwise
  its state is preserved and the result marks that membership may have changed
  and reviewed recovery is required. General health, cleanup, removal, and
  replacement remains a separate contract below.

### Implemented Scylla 2026.2 dead-node replacement contract

- The fifteenth available production source targets exactly one newly
  provisioned replacement with the failed node's stable logical ID but a
  distinct provider identity. Current trust/inventory/observation plus exact
  empty storage, ScyllaDB patch release, configuration, datacenter, rack, seeds,
  and intended post-state are mandatory.
- A quorum of healthy, schema-agreed, idle survivors must still report the exact
  old Host ID as DN. Independent old-target reachability evidence must remain
  unavailable, the replacement must be absent from the ring, no topology
  operation may be active, and any prior or completed `removenode` attempt
  refuses replacement.
- Narrow authorization binds the operation, stable ID, old Host/provider IDs,
  new provider identity, storage/config/health/topology/post-state, observation,
  inventory, and trust digests. Generic approval is insufficient.
- Immediately before mutation, the role rechecks survivor views and replacement
  package/config/service/empty-data state. It rejects obsolete
  `replace_address` and `replace_address_first_boot` keys, then atomically adds
  only `replace_node_first_boot: <dead-host-id>` to the validated
  `/etc/scylla/scylla.yaml` while `scylla-server` is masked and inactive.
- Systemd unmask/start is the irreversible boundary. Bounded survivor
  `nodetool gossipinfo`, `status`, `describecluster`, and `netstats` polling
  proves one new Host ID is UN in the expected datacenter/rack, the old Host ID
  is absent, all survivors remain UN, schema agrees, streaming is idle, and the
  post-topology is exact. No IP address identifies membership.
- Strict `deploy-scylla-vms.ansible-scylla-replace-dead/v1` evidence retains
  hashed old/new Host IDs and provider identities, stable ID, pre/post and
  prerequisite digests, status/streaming state, retained-key truth, repair/RBNO
  status, mutation boundary, recovery requirement, and bounded blockers.
  Failure never removes, forces, destroys, wipes, or blindly restarts.
- This slice performs no repair. `repair_required=true` blocks operation
  finalization unless strict RBNO-enabled-and-complete evidence makes it false;
  otherwise a later reviewed repair or Manager-evidence slice must complete
  before post-scale cleanup and finalization.

### Implemented Scylla 2026.2 direct repair contract

- The sixteenth available production source targets exactly one validated
  Scylla stable ID, serially and fatally, for either mandatory
  `post-replacement` repair or an explicitly reviewed `post-bootstrap` repair.
  No generic maintenance, keyspace, table, datacenter, or primary-range mode is
  accepted.
- Current complete cross-view health must prove every expected member UN with
  exact Host ID/datacenter/rack identity, one schema, no streaming, exact 2026.2
  patch version, current observation/inventory/trust/config/storage bindings,
  passed capacity and quorum evidence, and no competing topology or maintenance
  operation. Narrow authorization binds all of those facts and the exact source
  replacement/bootstrap result.
- Complete enabled RBNO replacement evidence may return a strict no-op. RBNO is
  never inferred from the ScyllaDB version. Bootstrap repair cannot use the RBNO
  skip.
- Immediately before mutation, fixed argv-form `nodetool info`, `status`,
  `describecluster`, `netstats`, `compactionstats`, and `version` checks repeat
  the identity, health, schema, streaming, pending-work, and version gates. The
  only mutating command is foreground `nodetool repair`, with a bounded long
  timeout and no shell, detached process, arbitrary option, `-pr`, datacenter,
  keyspace, or table selector.
- Exit zero alone is insufficient. The same full postchecks must pass with no
  pending repair or compaction work. Direct command evidence is operational,
  not cryptographic proof, so its successful result remains explicitly
  review-required; a separately modeled Manager result can be added later.
- Strict `deploy-scylla-vms.ansible-scylla-repair/v1` evidence contains reason,
  status/RBNO skip, stable target, hashed Host ID, pre/post health and source
  digests, command/completion evidence, mutation boundary, review/recovery
  truth, and bounded blockers. Timeout or interruption records a started
  boundary, requires recovery review, and prohibits automatic retry.

### Implemented Scylla 2026.2 post-expansion cleanup contract

- The seventeenth available production source targets exactly one validated
  Scylla stable ID, serially and fatally, after a completed healthy `add-node`
  or `scale-out` topology change. Python invokes one target per execution and
  journals every node boundary.
- The target must belong to the exact 2026.2 eligible set: pre-existing
  survivors, plus earlier joined nodes when a multi-node scale-out requires
  cleanup on all nodes except the last node added. The last joined node is
  always refused.
- Current complete cross-view health must prove every expected member UN with
  exact Host ID/datacenter/rack identity, one schema, no streaming, and the
  exact post-expansion topology. Current observation/inventory/trust/config/
  storage digests, sufficient free disk and compaction headroom, no competing
  topology or maintenance work, and any required completed repair/RBNO result
  are mandatory.
- Narrow reviewed authorization binds operation ID, exact target/Host ID,
  topology-change and repair results, health capture/digest, post-topology,
  disk-headroom evidence, and every current provenance digest. A prior started
  cleanup refuses blind execution.
- Immediately before mutation, fixed argv-form `nodetool info`, `status`,
  `describecluster`, `netstats`, `compactionstats`, and `version` checks repeat
  identity, health, schema, streaming, version, and pending-work gates. The only
  mutating command is foreground `nodetool cleanup`, with a bounded long
  timeout and no shell, background process, parallel target, or arbitrary
  keyspace/table option.
- Exit zero alone is insufficient. Bounded fixed-command polling must prove no
  pending cleanup/compaction work and restore exact healthy cluster evidence.
  Timeout, interruption, command failure, pending work, or post-health failure
  stops the sequence, requires journaled recovery review, and never triggers an
  automatic retry or proceeds to the next node.
- Strict `deploy-scylla-vms.ansible-scylla-cleanup/v1` evidence contains only
  status, stable target, hashed Host ID, topology-change/repair and pre/post
  health digests, command/pending-work evidence, mutation boundary, recovery
  truth, and bounded blockers. It contains no address, raw command output,
  provider identifier, or secret.

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

**Implemented local contract (26.9.1):**

- `deploy-scylla-vms.ssh-trust/v1` is persisted only at
  `ansible/trust.json` under the matching held cluster lock. It binds each
  confirmed key and the complete record to cluster UUID/name/provider, current
  Terraform observation and inventory generations/digests, stable logical and
  provider IDs, canonical IP endpoint and port, selected stable jump ID,
  capture/confirmation provenance and timestamps, generation, and entry/file
  digests. Strict owner/type/link/generation/rollback checks and atomic JSON
  replacement match the other state stores.
- The current deliberate host-key policy accepts only `ssh-ed25519` and
  `ecdsa-sha2-nistp256`. The parser validates base64 and the SSH wire-format
  algorithm/key shape, computes OpenSSH SHA-256 fingerprints, and rejects weak
  or unknown algorithms, malformed keys, algorithm/blob disagreement,
  duplicates, endpoint collisions, identity changes, and changed keys. Changed
  trust always requires a separately reviewed replacement workflow.
- Controlled direct `ssh-keyscan` and local `ssh-keygen -F` builders use exact
  argument arrays, canonical state working paths, minimal environments, bounded
  output/time, and the shared no-shell runner. Scan output creates candidates
  only. Promotion requires an explicit operator confirmation or an independently
  supplied matching fingerprint; generic `--yes` never grants trust.
- Portable OpenSSH does not provide a safe `ssh-keyscan` ProxyJump interface,
  so the direct scanner still refuses private-through-jump input and no
  interpolated remote shell or unchecked proxy is allowed. The reviewed
  alternative is the internal `routed-keyscan` Ansible support source: after
  current jump trust is complete, it reaches exactly that jump through the
  generated strict host-key-checking configuration and runs canonical
  `/usr/bin/ssh-keyscan` there against only bounded inventory-derived RFC 1918
  targets. Its endpoint payload is `no_log`; only strict address-free candidate
  evidence crosses the event boundary. Candidate collection never grants
  trust. First trust still requires explicit operator confirmation or an
  independently supplied matching fingerprint, and existing/changed trust
  remains blocked for the separately reviewed replacement workflow.
- `known_hosts` and `ssh_config` are deterministic owner-only derivatives of
  typed trust and inventory. SSH config uses only stable aliases, canonical
  addresses/ports/users, `ProxyJump` stable IDs, `StrictHostKeyChecking yes`,
  and the per-cluster known-hosts path; arbitrary SSH options and identity paths
  are absent.
- Routing supports zero, one, or multiple jumps. The currently implemented
  multi-jump policy exactly matches Terraform: choose from sorted stable jump
  IDs using the first eight hexadecimal digits of SHA-256(logical ID) modulo
  jump count. Validation rejects missing/unknown/non-jump/looping routes,
  policy ambiguity, public endpoints on private roles, untrusted jumps, and any
  provider/address/route difference from confirmed trust.
- `deploy-scylla-vms.ansible-readiness/v1` reports fresh/stale/unknown/conflict
  source and machine evidence, complete/incomplete/changed trust, valid/invalid/
  unknown routes, source generations/digests, redacted fingerprint summaries,
  and deterministic blockers for every operation class. Every production
  Ansible execution requires a report bound to the exact inventory with no
  blocker. Syntax/local-fixture checks are explicitly exempt. Local `show`
  reports these facts without exposing key blobs, addresses, provider IDs, or
  paths and without making an external call.

These trust collection and promotion contracts are internal APIs. No CLI
operation currently discovers, routes, confirms, or writes keys. The public
read-only `check-jump-hosts` workflow does not call them or imply private-host
trust.

## 9. Operation workflows

Every operation uses the common phase model: parse/resolve, lock, load metadata,
reconcile, validate preconditions, plan, confirm, execute, verify, journal, and
unlock. Read-only or no-change operations explicitly mark inapplicable phases
instead of pretending to plan/apply or seek unnecessary confirmation. A phase
that mutates state records durable non-secret completion evidence so an
interrupted operation can safely resume after revalidation; read-only operations
need not create a journal.

The implemented deploy PLAN composition is deliberately narrower than plan
creation or apply. After the immutable
`deploy-scylla-vms.terraform-plan-checkpoint/v1` exists, the deploy-only internal
composer reloads it from the canonical operation path under the same matching
held lock, revalidates its initial journal preimage and current desired/tfvars/
source/backend/state/toolchain bindings, and appends exactly one
`PLAN/validated` event to the existing `deploy-scylla-vms.operation/v1` journal.
That event contains only the checkpoint digest and bounded summary code
`terraform-plan-reviewed`; journal status and phase remain
`IN_PROGRESS/PLAN`. The checkpoint-first ordering permits exact retry after a
journal-write failure, while an already exact generation-2 event is reused
without a duplicate write. Conflicting, advanced, terminal, execution, stale,
tampered, or ambiguous history fails closed. No companion is needed because
common journal v1 already legally carries this digest binding; counts,
classifications, booleans, and address-free scope digests stay in the
independently versioned redacted composition report. This layer collects no
authorization, marks no approval, constructs no apply command, invokes no tool,
and crosses no destructive boundary.

The implemented internal Ansible checkpointing slice stops before execution.
Once an existing common journal contains the exact operation-plan checkpoint, a
separate matching-lock API may atomically persist its immutable request/plan
companion record. For an unblocked ready non-read-only plan, another
matching-lock API may then persist the immutable authorization companion while
leaving that journal at the exact PLAN generation/digest. It applies the class
and operation-specific CLI policy above, stores normalized proof enums/digests
only, and keeps wipe/restart/destructive-scope proofs separate from ordinary
confirmation. Resume validation is strictly offline and successful only while
all normalized request, selected-target, plan, catalog, packaged-source,
readiness, observation, inventory, trust, binding, authorization, and journal
bindings remain unchanged and fresh. Read-only operations require no
authorization record. Any confirm-or-later journal phase, terminal/interrupted
status, destructive boundary, malformed or unknown record, replay,
cross-operation/cluster/scope record, or missing/conflicting required history is
a non-resumable state. The validator returns evidence only; it does not
transition the journal, invoke a runner, or authorize execution.

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
| `--oci-vcn-cidr` | Canonical RFC 1918 IPv4 CIDR, prefix `/16` through `/30` | Required with `create`; forbidden with `existing` | `DEPLOY_SCYLLA_VMS_OCI_VCN_CIDR` | Define the managed VCN range. |
| `--oci-subnet` | Repeatable `ROLE=OCID`; roles `scylla`, `manager`, `monitoring`, `jump-host` | Required for each deployed role with `existing`; unset with `create` | No | Map roles to existing subnets without comma parsing. |
| `--oci-private-subnet-cidr` | Repeatable `ZONE=CIDR` | Exactly one per deployed zone with `create`; forbidden with `existing` | No | Define non-overlapping per-zone private subnets for Scylla and service hosts. |
| `--oci-public-subnet-cidr` | Repeatable `ZONE=CIDR` | Required only for zones containing public jump hosts; otherwise forbidden | No | Define public-routed subnet ranges without assigning public IPs to private roles. |
| `--oci-public-jump-hosts` | Boolean flag | `false` | `DEPLOY_SCYLLA_VMS_OCI_PUBLIC_JUMP_HOSTS` | Explicitly permit public IP assignment to jump hosts only. |
| `--operator-cidr` | Repeatable canonical IPv4/IPv6 CIDR | Required when policy creates operator ingress; no default | No | Bound SSH/approved operator endpoint ingress. |
| `--ssh-user` | Non-empty OS user string | Image/provider-derived on deploy; otherwise Persisted | `DEPLOY_SCYLLA_VMS_SSH_USER` | Set/assert remote login user. |
| `--ssh-public-key-path` | Readable public-key file path | Required when creating hosts unless provider bootstrap supplies an approved key | `DEPLOY_SCYLLA_VMS_SSH_PUBLIC_KEY_PATH` | Supply public bootstrap material only. |

`--network-mode existing` requires `--oci-vcn-id` and one unique
`--oci-subnet ROLE=OCID` for every role with a nonzero host count. `create`
forbids those existing-resource selectors and requires an explicit VCN CIDR plus
one non-overlapping RFC 1918 private subnet per canonical zone. Public subnet
CIDRs are required only for zones assigned public jump hosts. Private-key input
has no CLI flag.

Image selection uses per-role
`--scylla-image-*`, `--manager-image-*`, `--monitoring-image-*`, and
`--jump-host-image-*` flag families. Each family has operating-system,
operating-system-version, and version-match fields. Deploy requires OS/version
for every deployed role; no OS default or Scylla support implication is
inferred.

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
  hosts, then `ansible/playbooks/scylla-install.yml` and
  `ansible/playbooks/scylla-configure.yml` on `scylla`.
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

The persisted initial deploy mapping is the historical immutable 21-position
expansion of this list and omits an explicit `scylla-bootstrap` step between
`scylla-configure` and the first `scylla-health`. That omission must not be
silently repaired by rewriting or reordering an existing operation plan.
Post-configuration reconciliation must stop with `bootstrap-plan-required` and
`bootstrap-step-unmodeled`, keep bootstrap/empty-cluster/topology/seed/health/
capacity evidence not performed, and expose no mutation authorization until a
separately versioned deploy-bootstrap context and plan bind the reviewed
initial-seed order, exact empty-cluster proof, topology/seed/capacity gates, and
per-target health checkpoints.

The implemented internal bootstrap-planning boundary persists separate
`deploy-scylla-vms.ansible-deploy-scylla-bootstrap-context/v1` and
`deploy-scylla-vms.ansible-deploy-scylla-bootstrap-plan/v1` companions; it does
not modify the historical mapping. Its canonical API accepts only the state
root, cluster name, operation UUID, matching held deploy lock, and an optional
normalized reviewed new-cluster proof. It reloads the full chain through exact
post-configuration reconciliation and binds the initial Terraform
absent-state proof or an exact create-only/drift-free initial-observation apply
proof, current observation, inventory, trust, readiness, storage, install,
configuration, packaged source, catalog, and unchanged VERIFY journal.
New-cluster intent, reviewed empty live-cluster state, prior-membership absence,
and bootstrap capacity sufficiency are the only caller-owned proof facts;
missing or unknown facts are blockers.

The owner refuses prior bootstrap/membership artifacts, requires every Scylla
service to remain masked/inactive and never started by any bound install or
configuration action, and derives the exact stable set, topology, configured
seed, and target order without caller targets, modes, seeds, variables, or
addresses. The configured seed is first in `initial-seed` mode. Remaining
targets are ordered deterministically by topology and stable identity and use
`join-existing`, serial one. Each join remains waiting for its preceding target
and a complete current cluster-health checkpoint proving healthy survivors,
target absence, capacity, schema agreement, and completed prior membership.
Expected Host IDs remain explicitly unknown before start. Only a fully proven
initial seed may be marked authorization-required; this layer creates no
authorization or execution record, invokes no runner, and does not change the
journal. Context is durably written before plan, an exact context-only prefix
can recover, exact records are reusable, and every changed proof or provenance
fails closed. Persisted/public projections contain only counts, bounded enums,
and redacted digests, never addresses, seed identities, configuration values,
provider IDs, or Host IDs.
This bootstrap ordering and proof binding is project orchestration scope, not a
verified upstream ScyllaDB Ansible role gap, so it creates no
`UPSTREAM_TODO.md` entry.

The implemented internal initial-seed authorization boundary persists distinct
`deploy-scylla-vms.ansible-deploy-scylla-bootstrap-authorization-proof/v1`,
`deploy-scylla-vms.ansible-deploy-scylla-bootstrap-authorization/v1`, and
`deploy-scylla-vms.ansible-deploy-scylla-bootstrap-authorization-report/v1`
schemas. Its canonical API accepts only the state root, cluster name, operation
UUID, matching held deploy lock, and one normalized proof. It reloads and
exactly reproduces the complete chain plus immutable bootstrap context/plan,
then derives the sole sequence-one `initial-seed` target and its mode, full
order, topology, seed policy, exact package version, storage/configuration/
capacity/source evidence, and empty-cluster proof as redacted digests. Caller
targets, modes, order, seeds, values, commands, variables, and paths are
forbidden.

The registry classifies `scylla-bootstrap` as sensitive, so ordinary
interactive or CLI `--yes` approval is required. Crossing the irreversible
initial membership-start boundary additionally requires a separate exact
digest-only initial-seed scope acknowledgement supplied interactively or by an
explicit narrow proof. `--yes` supplies only ordinary approval and never the
narrow proof. `--allow-destructive` and destructive-scope proof are
inapplicable and refused because this step is sensitive rather than
destructive. No approval bypasses empty-cluster, identity, storage,
configuration, masked/inactive and never-started service, topology, seed,
capacity, trust, readiness, source, journal, or drift gates.

Only the first initial seed can be authorized. Every `join-existing` step stays
outside the authorization with its exact waiting-health digest and cannot be
included until a later separately reviewed health-checkpoint continuation.
The owner writes only
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-authorization.json`
as immutable owner-only state, marks it unconsumed with execution unavailable,
and leaves the common journal and prior artifacts byte-for-byte unchanged.
Persisted and report projections retain bounded enums, counts, and digests
only; addresses, seed/configuration values, Host IDs, provider IDs, commands,
variables, paths, free text, credentials, and secrets are absent. This layer
does not invoke a runner, start Scylla, create execution evidence, finalize,
or add CLI/public wiring.

The implemented internal initial-seed execution boundary persists distinct
`deploy-scylla-vms.ansible-deploy-scylla-bootstrap-execution-binding/v1`,
`deploy-scylla-vms.ansible-deploy-scylla-bootstrap-execution/v1`,
`deploy-scylla-vms.ansible-deploy-scylla-bootstrap-evidence-entry/v1`,
`deploy-scylla-vms.ansible-deploy-scylla-bootstrap-evidence/v1`, and
`deploy-scylla-vms.ansible-deploy-scylla-bootstrap-execution-report/v1`
schemas. Its canonical API accepts only the state root, cluster name, operation
UUID, matching held deploy lock, controlled runner, exact sibling Ansible
executable pair, and explicit supported toolchain dependency. It reloads and
reproduces the complete chain through the bootstrap context, plan, and
unconsumed authorization before effects. The exact sequence-one target, its
`initial-seed` mode, topology, configured sole seed, two configuration-file
identities, current storage/package version, source, variables, and anchored
command are derived only from canonical state. Caller scope, target, mode,
topology, seed, version, variables, command, path, result, and retry controls
are forbidden.

The execution owner writes generation one `prepared` before invocation and
durable `started` immediately before the one controlled
`scylla-bootstrap` call. `started` consumes both the ordinary sensitive
approval and the exact narrow initial-membership-start acknowledgement without
rewriting the immutable authorization. Catalog policy must remain
source-available sensitive, exact-one-target, serial one, fatal, and
check-mode-refused. The exact packaged source and controlled command are bound
by digest; the owner probes only the exact sibling Ansible executables before
the effect.

Strict parsing must prove exact target and `initial-seed` mode, current
prerequisite digests, pre-start masked/inactive revalidation, the
systemd unmask/start boundary, bounded local CQL readiness, and argv-form
nodetool Host-ID, Up Normal ring/topology, schema-agreement, and idle-streaming
evidence. Exit zero is never sufficient. Persisted semantic evidence contains
only the stable ID, hashed Host/ring identities, bounded topology/version/
status booleans, and digests. Addresses, raw Host IDs, output, configuration,
seed identities, commands, variables, protected paths, credentials, and
secrets are absent.

A strict success becomes terminal `succeeded` with the node preserved and
automatic retry disabled. A strict source-contract failure is terminal
`failed`, permanently manual-recovery-required, and also no-retry. A node that
may have joined remains preserved and unremasked; remask evidence is accepted
only for the source's `service-unmasked-started` result that proves the target
never joined. Every crash, timeout, interruption, unreachable/nonzero or
malformed result, post-call drift, evidence-write failure, or terminal-write
failure after `started` is uncertain and permanently forbids automatic retry,
restart, destroy, or removenode. An exact prepared prefix may resume because no
call could have occurred; exact successful re-entry makes zero process calls.
The records live only at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-execution.json`
and
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-bootstrap-evidence.json`.
Local `show` validates both.

This slice does not authorize or execute `join-existing`, reconcile cluster
health, transition the common journal, finalize deploy, or add CLI/public
wiring. The journal and all prior companions remain byte-for-byte at
`IN_PROGRESS/VERIFY`. This ownership and recovery policy is project
orchestration rather than a verified upstream ScyllaDB Ansible role gap, so it
adds no `UPSTREAM_TODO.md` entry.

The implemented complete-cluster health checkpoint binds the successful
initial seed as the exact current member prefix and verifies UN membership,
survivor/seed health, target absence, topology, schema agreement, idle
streaming, service/API/CQL/storage readiness, and exact source/provenance. Its
generic Scylla-health policy projection truthfully leaves unauthenticated
replication and backup checks `not-performed` and quorum/capacity checks
`unknown`; those states are not silently promoted.

The separately versioned initial-deploy join-safety boundary resolves the
operation-specific policy before the first `join-existing` authorization. PLAN
requires current canonical target-absence, survivor/seed health, topology,
schema, streaming, completed-prior-membership, and target storage evidence plus
one current digest-bound independent capacity proof. Replication, quorum, and
Manager backup-policy evidence are stronger removal/replacement gates and are
`not-applicable` for this initial-deploy join class; `not-applicable` is not a
pass and is permitted only by this explicit policy. Capacity remains required:
failed, unknown, stale, or binding-mismatched proof cannot authorize a join.

The owner persists immutable owner-only
`deploy-scylla-vms.ansible-deploy-scylla-join-safety-context/v1`,
`deploy-scylla-vms.ansible-deploy-scylla-join-safety-evidence/v1`, and
`deploy-scylla-vms.ansible-deploy-scylla-join-safety-reconciliation/v1` only
under `<cluster-root>/operations/`. Records bind the exact first waiting target,
survivor set, topology, health, storage, configuration, source, proof freshness,
and gate digests without raw CQL/query output, addresses, provider IDs,
credentials, configuration values, or unhashed Host IDs. Only the first waiting
join may become `authorization-required`; later joins remain waiting for their
own preceding membership and complete current health checkpoint. Exact reuse
is zero-write and conflicts fail closed. This boundary creates no
authorization/execution record, invokes no process, leaves the common journal
unchanged at `IN_PROGRESS/VERIFY`, has no public/CLI wiring, and remains project
orchestration rather than an upstream-role gap. The next slice is a distinct
sensitive `join-existing` authorization owner for only the reconciled first
join scope.

The implemented first-join authorization boundary persists distinct
`deploy-scylla-vms.ansible-deploy-scylla-join-authorization-proof/v1`,
`deploy-scylla-vms.ansible-deploy-scylla-join-authorization/v1`, and
`deploy-scylla-vms.ansible-deploy-scylla-join-authorization-report/v1`
schemas. Its canonical API accepts only state-root and cluster identity, one
operation UUID, the matching already-held deploy lock, and one normalized
proof. It reloads and reproduces the full bootstrap plan, successful initial
execution/evidence, complete current health execution/evidence/checkpoint,
join-safety context/evidence/reconciliation, and their complete current
Terraform/observation/inventory/trust/readiness/storage/install/configuration/
source/catalog/journal chain before persistence. Caller target, mode, scope,
survivor, seed, topology, configuration, version, storage, command, variables,
paths, and free-form input are forbidden.

The owner derives only exact sequence two when it remains the first reconciled
`authorization-required` `join-existing` target. It binds that target and mode,
the bootstrap/health/safety step identities, current survivor and active-seed
set, topology/schema/membership, target topology, package version, storage,
configuration, capacity, seed policy, packaged source, all required gate
decisions, and the three join-safety records through redacted counts and
digests. Every later join remains `waiting-for-preceding-complete-health` and
outside the authorized scope. Any missing, failed, unknown, stale, changed, or
binding-mismatched target-absence, capacity, survivor/seed-health, schema,
streaming, completed-prior-membership, topology, storage, trust, readiness,
source, journal, or drift gate fails closed.

Because the registry class is sensitive, authorization requires ordinary
interactive or PLAN-permitted `cli-yes` approval plus a separate exact
digest-only target/mode/scope acknowledgement supplied interactively or by an
explicit narrow proof. `cli-yes` never supplies the narrow proof.
`--allow-destructive` and destructive-scope proof are inapplicable and refused.
The sole immutable owner-only record lives at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-join-authorization.json`,
remains unconsumed with execution unavailable, and leaves the common journal
and every prior artifact byte-for-byte unchanged at `IN_PROGRESS/VERIFY`.
Persisted and report projections contain only bounded enums, counts, and
digests; addresses, raw Host IDs, seed identities, provider IDs, configuration
values, commands, variables, protected paths, prompts/free text, credentials,
and secrets are absent. Local `show` validates the record. This layer invokes
no runner, starts no service, creates no execution/evidence record, finalizes
nothing, and adds no public/CLI wiring. The next slice is a distinct
operation-bound exact first-join execution owner with durable intent and
no-retry recovery semantics. This authorization ownership is project
orchestration, not a verified upstream ScyllaDB Ansible role gap, so it adds no
`UPSTREAM_TODO.md` entry.

The implemented first-join execution owner persists independently versioned
owner-only `deploy-scylla-vms.ansible-deploy-scylla-join-execution/v1`,
`deploy-scylla-vms.ansible-deploy-scylla-join-evidence/v1`, and redacted
execution-report v1 contracts. Its canonical API accepts only state-root and
cluster identity, one operation UUID, the matching held deploy lock, the
controlled runner, and one exact sibling Ansible executable/toolchain
dependency. It reloads and reproduces the complete immutable bootstrap,
initial-seed, current-health, join-safety, first-join authorization, source,
catalog, and VERIFY-journal chain before every effect.

Only the authorized reconciled sequence-two `join-existing` target is derived.
The owner derives its exact target, order, topology, package, storage,
configuration, active seeds, healthy survivors, capacity proof, runtime
variables, packaged source, and anchored command from canonical records. It
persists retry-safe `prepared`, then durable `started` immediately before the
sole exact-one-target, serial-one, check-mode-refused `scylla-bootstrap`
invocation. `started` consumes both authorization decisions without rewriting
the authorization. Strict parser evidence must reproduce the target, mode,
prerequisites, source, command, variable intent, pre-start gates, CQL
readiness, membership, topology, schema agreement, and completed streaming;
exit zero alone is insufficient.

The execution and evidence artifacts live only at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-join-execution.json`
and
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-join-evidence.json`.
Exact successful re-entry is zero-process. Any crash, timeout, interruption,
nonzero/unreachable/malformed result, post-start drift, or post-effect
persistence failure is permanently manual-recovery/no-retry. Later joins stay
waiting, all prior artifacts and the common journal remain byte-for-byte at
`IN_PROGRESS/VERIFY`, and no public/CLI path is added. Persisted evidence and
reports retain only bounded states, booleans, counts, stable identity, and
redacted digests; addresses, raw Host IDs, provider IDs, seed/configuration
values, output, commands, variables, environment, protected paths, credentials,
and secrets are absent. Local `show` validates both records. This is project
orchestration, not a new upstream-role workaround, so `UPSTREAM_TODO.md`
remains unchanged.

The implemented post-first-join health owner performs a fresh exact
complete-current-set `scylla-health` run rather than reconciling the
sequence-two bootstrap result as health. The pre-join health checkpoint is
intentionally bound to the initial-seed prefix and cannot represent the joined
membership, while bootstrap evidence proves only its target-local result. The
owner therefore canonically reloads the complete chain through successful
first-join execution/evidence, consumed ordinary and narrow authorization,
pre-join health, join safety, source/catalog, and the unchanged VERIFY journal,
then queries exactly the initial seed plus sequence-two target. It reuses the
existing controlled Ansible service, payload builder, source hash validation,
and strict `scylla-health` parser; no parallel command or parser contract is
introduced.

The owner persists independently versioned owner-only
`deploy-scylla-vms.ansible-deploy-scylla-join-health-execution/v1`,
`deploy-scylla-vms.ansible-deploy-scylla-join-health-evidence/v1`, and
`deploy-scylla-vms.ansible-deploy-scylla-join-health-reconciliation/v1` only
at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-join-health-{execution,evidence,reconciliation}.json`.
It records durable `started` before the sole complete-set call and requires
exact hashed Host-ID membership, all members UN, cross-view identity/topology
and schema agreement, idle streaming, service/API/CQL readiness, and current
storage/configuration/source provenance. Exit zero and first-join bootstrap
success are insufficient. Crash, timeout, interruption, malformed or
semantically incomplete output, post-call drift, or post-effect persistence
uncertainty is permanent manual-recovery/no-retry. An exact succeeded
execution/evidence prefix may recover only the missing reconciliation without
a process call; exact complete re-entry is zero-process and zero-write.

Reconciliation marks only sequence one and sequence two health-succeeded and
derives at most sequence three. Generic health policy truth remains exact:
replication and Manager backup policy are `not-performed`, while quorum and
capacity are `unknown`, so sequence three remains blocked until a later
operation-specific safety boundary independently resolves its reviewed gates.
Every later join remains waiting. Records and reports retain only bounded
states, counts, stable IDs, and redacted digests without addresses, raw Host
IDs, provider IDs, seed/configuration values, routes, commands, variables,
environment, raw output, protected paths, credentials, or secrets. Local
`show` validates all three records. The owner leaves every prior artifact and
the common journal byte-for-byte at `IN_PROGRESS/VERIFY`, creates no
authorization, finalizes nothing, and adds no public/CLI wiring. This is
project orchestration rather than an upstream-role workaround, so
`UPSTREAM_TODO.md` remains unchanged. The next slice is the distinct safety
context/evidence/reconciliation boundary for the immediate sequence-three join
before that target can be authorized.

The implemented sequence-three join-safety owner persists independently
versioned owner-only context, evidence, reconciliation, and report v1
contracts at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-sequence-three-join-safety-{context,evidence,reconciliation}.json`.
Its internal API accepts only canonical state-root/cluster identity, one
operation UUID, the matching held deploy lock, and the existing normalized
typed safety proofs. It reloads the complete chain through terminal-success
sequence-two execution, consumed authorization, the fresh post-first-join
complete-set health checkpoint, bootstrap plan, current infrastructure and
Ansible provenance, and the unchanged VERIFY journal. It derives only the
contiguous sequence-three `join-existing` target; sequences one and two remain
health-succeeded and every later sequence remains waiting.

Sequence three becomes `authorization-required` only when all canonical
membership, survivor/seed health, cross-view topology/schema/streaming,
target-absence, target storage/configuration/package, route/trust/readiness,
and no-competing-operation gates pass and exact independent backup-policy,
capacity, quorum, and replication proofs all pass. Unknown, failed, stale,
missing, duplicate, or drifted evidence blocks without inference. Context is
written before evidence and reconciliation; exact prefixes recover, exact
records are zero-write reusable, and conflicts never overwrite or adapt state.
Local `show` validates all three artifacts. Records and reports retain only
bounded states, counts, stable IDs, and redacted digests. This owner creates no
authorization or execution, advances no later sequence or journal phase, and
adds no public/CLI wiring. The next slice is the distinct sequence-three
sensitive join authorization owner. No new upstream-role workaround was
introduced, so `UPSTREAM_TODO.md` remains unchanged.

The implemented sequence-three join authorization owner persists independently
versioned immutable owner-only proof, authorization, and report v1 contracts at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-sequence-three-join-authorization.json`.
Its internal API accepts only canonical state-root/cluster identity, one
operation UUID, the matching held deploy lock, and one normalized proof. It
reproduces the full chain through terminal sequence-two execution with consumed
proofs, fresh complete-set post-first-join health, exact sequence-three safety,
current infrastructure/Ansible provenance, and the unchanged VERIFY journal.

Only the reconciled sequence-three `join-existing` target can be authorized.
The record binds its target/mode/order/topology, survivor and active-seed sets,
membership/schema/streaming, package/storage/configuration, target capacity,
independent backup/capacity/quorum/replication proofs, packaged source, and
safety identities through bounded counts, enums, and digests. Every later join
remains waiting and outside scope. Sensitive policy requires ordinary
interactive or PLAN-permitted `cli-yes` approval plus a separate exact
digest-only target/mode/scope acknowledgement; `cli-yes` alone is insufficient,
and destructive proof is refused as inapplicable. Exact reuse is zero-write;
changed proof, gate, scope, provenance, or current state requires a new
operation. Authorization remains unconsumed, execution/public workflow remain
unavailable, and prior records plus the journal stay byte-for-byte unchanged.
Local `show` validates the redacted record. This layer invokes no process,
creates no execution/evidence record, and adds no CLI/public wiring. The next
slice is the distinct sequence-three exact-join execution owner. No upstream
role workaround was introduced, so `UPSTREAM_TODO.md` remains unchanged.

The implemented sequence-three exact-join execution owner persists distinct
owner-only
`deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-execution/v1`,
semantic-evidence v1, and redacted report v1 contracts at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-sequence-three-join-{execution,evidence}.json`.
Its internal API accepts only canonical state-root/cluster identity, the
operation UUID, the matching held deploy lock, a controlled runner, and exact
validated sibling Ansible executables/toolchain. It canonically reproduces the
full chain through successful sequence two, fresh post-first-join health, exact
sequence-three safety and authorization, current infrastructure/Ansible
provenance, source/catalog, and the unchanged VERIFY journal before every
effect.

Only the authorized reconciled sequence-three `join-existing` target is
derived. Its exact order, topology, package/storage/configuration, healthy
survivor and active-seed sets, capacity and policy evidence, source, protected
variables, and anchored command are rebuilt internally; caller-selected
execution scope or retry controls are absent and every later join stays
waiting. A retry-safe `prepared` record precedes durable `started` intent;
`started` consumes ordinary and narrow authorization without rewriting it.
The sole call is the hash-checked, exact-one-target, serial-one,
check-mode-refused `scylla-bootstrap` source. Strict parser and provenance
parity plus target/mode/prerequisite/pre-start, CQL, membership, topology,
schema, and streaming semantics are required beyond exit zero, and semantic
evidence is durable before terminal success.

Every post-start crash, timeout, interruption, nonzero/unreachable/malformed
result, drift, or persistence uncertainty is permanent manual-recovery/no-
retry. Prepared recovery is allowed only before invocation; exact terminal
success re-entry is zero-process and zero-write. Local `show` validates both
records. Evidence and reports remain bounded and redacted; prior artifacts and
the common journal remain byte-for-byte at `IN_PROGRESS/VERIFY`. This slice
does not run post-sequence-three health, advance a later join, finalize deploy,
or add public/CLI wiring. No upstream-role workaround was introduced, so
`UPSTREAM_TODO.md` remains unchanged. The next slice is the distinct fresh
complete-current-set post-sequence-three join health and reconciliation owner.

The implemented post-sequence-three join health owner performs a fresh exact
complete-current-set `scylla-health` run across the initial seed plus sequence
two and sequence three. It canonically reloads the full infrastructure,
storage/install/configuration, bootstrap, post-first-join health,
sequence-three safety/authorization/execution/evidence, source/catalog, and
unchanged VERIFY-journal chain. It requires terminal-success sequence-three
execution with consumed ordinary and narrow proofs and never treats bootstrap
success as current cluster-health evidence.

The owner reuses the existing hash-checked source, controlled service, payload
builder, and strict parser. It persists distinct owner-only post-sequence-three
health execution, evidence, and reconciliation v1 companions under
`<cluster-root>/operations/` and returns a separate bounded report v1
projection, recording durable `started` before the sole complete-set call.
Strict success requires exact unique hashed membership, all three members Up
Normal, cross-view identity/topology/schema agreement, idle streaming,
service/API/CQL readiness, and current storage/configuration/source provenance.
Generic policy truth remains exact: replication and backup are `not-performed`,
while quorum and capacity are `unknown`.

Every post-start process, parsing, drift, or persistence uncertainty is
permanent manual-recovery/no-retry. Exact completed re-entry is zero-process
and zero-write, while an exact execution/evidence-only prefix may recover only
the missing reconciliation. Reconciliation clears only sequence-three health:
a later planned join remains waiting for its own separately versioned safety
context, while a three-step plan reports bounded bootstrap-sequence-complete
and next-step-not-required truth. Prior records and the common journal remain
byte-for-byte at `IN_PROGRESS/VERIFY`; no later safety, authorization,
execution, finalization, or public/CLI wiring is created. Local `show` validates
all three redacted companions. This is project orchestration, not a new
upstream-role workaround, so `UPSTREAM_TODO.md` remains unchanged. The next
slice is the separately versioned safety context for sequence four when a later
planned join exists; otherwise no further bootstrap join slice is required.

The implemented generic later-join safety owner persists independently
versioned owner-only context/evidence/reconciliation v1 records per derived
sequence at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-later-join-sequence-<sequence>-safety-{context,evidence,reconciliation}.json`.
Its internal API accepts only canonical state-root/cluster/operation identity,
the matching held deploy lock, and the established normalized safety proofs.
It derives the exact first unfinished bootstrap-plan sequence from the immutable
plan and canonical contiguous completed prefix; callers cannot select a
sequence, target, order, mode, or runtime value. The current chain therefore
derives sequence four, while sequence-keyed immutable records allow each later
sequence `>=4` to coexist once its preceding execution and fresh complete-set
health records become canonical.

No remaining plan step returns strict `not-required`, accepts no proofs, and
writes no artifact. Otherwise the owner binds the complete healthy prefix,
target absence and provenance, current route/trust/readiness, source/catalog/
journal, no-competing-operation truth, and independent backup/capacity/quorum/
replication proofs. Unknown remains blocking. Only the immediate derived join
may become `authorization-required`; every later join stays waiting. Exact
prefix recovery and byte-identical reuse are supported, while a changed
same-sequence prefix, proof, or provenance conflicts with that immutable
artifact family. Local `show` validates all redacted records. This slice creates no
authorization, execution, health call, journal transition, or public/CLI
wiring. It adds no upstream-role workaround, so `UPSTREAM_TODO.md` remains
unchanged.

The implemented generic later-join authorization owner persists one
independently versioned immutable owner-only proof/authorization/report v1
contract per derived sequence at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-later-join-sequence-<sequence>-authorization.json`.
Its internal API accepts only canonical state-root/cluster/operation identity,
the matching held deploy lock, and one normalized approval proof. It reloads
and reproduces the complete current chain plus the exact generic later-join
safety context/evidence/reconciliation, then derives only the reconciliation's
first unfinished `join-existing` sequence `>=4`; callers cannot choose a
sequence, target, mode, order, topology, runtime value, or scope. A completed
bootstrap sequence accepts no proof, writes no authorization, and returns
strict `not-required`.

The authorization binds the exact completed prefix, target, order, healthy
survivors and active seed, membership/topology/schema/streaming, package,
storage, configuration, target capacity, independent backup/capacity/quorum/
replication proofs, source, and safety identities through bounded values and
digests. Sensitive policy requires ordinary interactive or PLAN-permitted
`cli-yes` approval plus a separate exact digest-only target/mode/sequence/scope
acknowledgement; `cli-yes` alone is insufficient and destructive proof is
refused as inapplicable. Every later step remains waiting and excluded. Exact
reuse is zero-write; changed sequence, proof, scope, gate, prefix, provenance,
or current state requires a new operation. Authorization remains unconsumed,
execution/public workflow remain unavailable, and prior records plus the
VERIFY journal stay byte-for-byte unchanged. Local `show` validates the
redacted record. This layer invokes no process and adds no execution, health,
CLI, or public wiring. It adds no upstream-role workaround, so
`UPSTREAM_TODO.md` remains unchanged.

The implemented generic later-join execution owner persists independently
versioned owner-only execution and semantic-evidence v1 records per sequence at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-later-join-sequence-<sequence>-{execution,evidence}.json`.
Its internal API accepts only canonical state-root/cluster/operation identity,
the matching held deploy lock, controlled runner, and exact sibling Ansible
executables/toolchain. It reloads the complete immutable chain through the
latest complete-set health, generic safety, and unconsumed authorization, then
derives only the authorized first unfinished `join-existing` sequence `>=4`.
Neither sequence, target, mode, order, scope, variables, command, result, nor
retry controls are caller inputs.

After full validation the owner records retry-safe `prepared`, durably records
`started` and consumes both approvals before one exact hash-checked
`scylla-bootstrap` call, persists strict address-free semantic evidence, and
only then records terminal success. Any uncertainty after `started` is
manual-recovery/no-retry; exact prepared recovery is pre-invocation only and
exact completed re-entry is zero-process/zero-write. Later joins remain waiting
for a separate fresh complete-set health checkpoint and safety context. The
VERIFY journal and prior records remain unchanged, local `show` validates both
records, and no health, CLI/public wiring, or upstream-role workaround is added.

The implemented generic post-later-join health owner derives the exact
terminal-successful sequence `>=4` from canonical sequence-keyed join records
and runs the existing hash-checked read-only `scylla-health` source over the
exact complete current stable-ID set. It persists immutable owner-only
execution, evidence, and reconciliation v1 records per sequence at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-post-later-join-sequence-<sequence>-health-{execution,evidence,reconciliation}.json`.
Durable `started` precedes the sole process call; strict complete unique
membership, Up Normal state, cross-view identity/topology/schema agreement,
idle streaming, service/API/CQL readiness, and storage/configuration
provenance are mandatory. Replication and backup remain `not-performed`;
quorum and capacity remain `unknown`.

Exact completed re-entry is zero-process/zero-write. Any uncertainty after
`started` is manual-recovery/no-retry. Reconciliation either marks the
bootstrap sequence complete or leaves only the next canonically derived join
waiting for its separately sequence-keyed safety stage. It never collects that
safety evidence, authorizes, or executes the next join. The VERIFY journal and
prior records remain unchanged, local `show` validates every sequence-keyed
record, and no CLI/public wiring or upstream-role workaround is added.

The implemented post-bootstrap deploy-mapping bridge canonically reloads the
complete chain through the immutable bootstrap plan, every exact contiguous
terminal-success bootstrap authorization/execution/evidence record, and the
final fresh complete-current-set health family selected by the plan's final
sequence. It handles initial-seed-only, sequence-two, sequence-three, and
generic sequence-keyed later-join completion without caller-selected status,
target, sequence, plan, result, path, command, or variable input. Missing,
extra, partial, prepared, started, failed, uncertain, stale, or drifted
artifacts fail closed.

The bridge persists only immutable owner-only
`deploy-scylla-vms.ansible-deploy-scylla-post-bootstrap-reconciliation/v1` at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-post-bootstrap-reconciliation.json`.
It proves the historical 21-position mapping unchanged, resolves only
`bootstrap-plan-required` / `bootstrap-step-unmodeled`, and binds the final
strict complete-set health evidence to mapping-position-thirteen
`scylla-health`. It advances only immediate mapping-position-fourteen
`manager-server` to `evidence-ready-authorization-required`; later Manager,
monitoring, final health/evidence, and finalization work does not leapfrog.
Replication and backup remain `not-performed`, quorum and capacity remain
`unknown`, exact reuse is zero-write, local `show` validates the companion, and
the common journal remains byte-for-byte at `IN_PROGRESS/VERIFY`. No
authorization, execution, process call, CLI/public wiring, or upstream-role
workaround is added.

The implemented internal mapped `manager-server` authorization/execution
boundary accepts only canonical state-root/cluster/operation identity, the
matching held deploy lock, normalized ordinary approval for authorization, and
the controlled runner plus exact sibling Ansible executables/toolchain for
execution. It reloads the complete verified infrastructure, deploy, bootstrap,
final-health, post-bootstrap bridge, source, catalog, controller, and
`IN_PROGRESS/VERIFY` journal chain. From that chain it derives exactly one
mapping-position-fourteen manager stable ID, Ubuntu 24.04 architecture, the
exact Manager 3.12 package/repository/authenticated-key provenance, install-only
variables, and the anchored hash-checked `manager-server` command. Caller
targets, packages, versions, repositories, keys, variables, commands, paths,
results, and retry controls are not accepted.

Execution persists independently versioned owner-only generation-guarded
`deploy-scylla-vms.ansible-deploy-manager-server-execution/v1` and
immutable-prefix
`deploy-scylla-vms.ansible-deploy-manager-server-evidence/v1` records under the
canonical operation paths. It records retry-safe `prepared`, durably records
`started` immediately before its sole controlled call, and consumes the whole
immutable authorization without rewriting it. Strict success requires exact
target/package/repository/key/source/command/provenance parity,
installed-or-no-change state, masked/inactive `scylla-manager`, and explicit
absence of backend configuration, general configuration, setup, registration,
Manager tasks, and service start. Evidence is durable before terminal success.
A crash, timeout, interruption, unreachable/nonzero or malformed result,
semantic mismatch, post-call drift, or evidence-write uncertainty after
`started` is manual-recovery/no-retry and forbids rollback, skip, or
continuation. Exact `prepared` recovery is allowed only before invocation;
exact success re-entry is zero-process/zero-write. Reports and evidence are
bounded and redacted, local `show` validates but does not project the records,
and the journal, authorization, bridge, prior plans, CLI/public surface, and
upstream-workaround inventory remain unchanged.

The implemented internal post-`manager-server` reconciliation owner accepts
only canonical state-root/cluster/operation identity and the matching held
deploy lock. It canonically reloads the full verified infrastructure,
historical deploy mapping, storage/install/configuration/bootstrap/final-health
bridge, Manager authorization/execution/evidence, source, catalog, and
unchanged `IN_PROGRESS/VERIFY` journal chain. Exact terminal success requires
consumed execution authorization, one complete Manager 3.12
installed-or-no-change result for the canonical manager target,
package/repository/authenticated-key/source/command parity, masked/inactive
`scylla-manager`, and no backend, configuration, setup, registration, task, or
service-start action. Every incomplete, uncertain, stale, conflicting, or
drifted state fails closed.

It persists only immutable owner-only
`deploy-scylla-vms.ansible-deploy-post-manager-server-reconciliation/v1` at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-manager-server-reconciliation.json`.
The record proves the historical 21-position mapping unchanged, marks only the
exact mapped `manager-server` instance evidence-bound succeeded, and evaluates
only the immediate next active mapped gate from current canonical evidence.
Read-only work may become `eligible`; mutating work may become only
`evidence-ready-authorization-required`; blocked gates retain their exact
blockers and no later gate leapfrogs. Exact reuse is zero-write, conflicts never
overwrite or adapt history, local `show` validates the bounded redacted record,
and all prior artifacts and the common VERIFY journal remain byte-for-byte
unchanged. This owner does not configure a Manager backend, register or start
Manager, infer Manager health, authorize, execute, invoke a process, finalize,
or add CLI/public wiring.

The implemented internal mapped `monitoring-stack` authorization owner accepts
only canonical state-root/cluster/operation identity, the matching held deploy
lock, and one normalized ordinary approval proof. It canonically reloads the
full verified infrastructure, historical deploy mapping, bootstrap/final
health, Manager authorization/execution/reconciliation, current monitoring-role
inventory, trust/readiness/base-OS, source/catalog, and unchanged
`IN_PROGRESS/VERIFY` journal chain. It derives only exact mapping-position
fifteen, one monitoring stable ID, Ubuntu 24.04 architecture, mutating class,
the digest-pinned official Scylla Monitoring 4.16.0 archive and component/source
provenance, and the archive-install-only policy. Docker installation or image
pulls, Compose/auth/targets, containers or service start, public binds, Manager
registration, Scylla start, and secrets remain forbidden.

Interactive or PLAN-permitted `cli-yes` ordinary approval is required;
destructive and narrow proof are refused as inapplicable and cannot bypass any
ordering, identity, OS, readiness, provenance, no-public-bind, or drift gate.
The owner persists only immutable owner-only
`deploy-scylla-vms.ansible-deploy-monitoring-stack-authorization/v1` at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-monitoring-stack-authorization.json`.
Exact reuse is zero-write; changed proof, scope, or provenance requires a new
operation. The authorization remains unconsumed, execution/public workflow
remain unavailable, local `show` validates the bounded redacted record, and
all prior artifacts plus the VERIFY journal remain byte-for-byte unchanged.
No process, host mutation, execution record, later-gate advancement, CLI/public
wiring, or upstream-role workaround is added.

The implemented internal mapped `monitoring-stack` execution boundary accepts
only that canonical state/operation identity and held deploy lock plus the
controlled runner and exact sibling Ansible executables/toolchain. It reloads
the complete verified infrastructure, deploy, bootstrap/final-health, Manager,
post-Manager, source/catalog/controller, authorization, and
`IN_PROGRESS/VERIFY` journal chain. From that chain it derives exactly one
mapping-position-fifteen monitoring stable ID, Ubuntu 24.04 architecture, the
digest-pinned official Scylla Monitoring 4.16.0 archive and component/source
provenance, install-only variables, and the anchored hash-checked
`monitoring-stack` command. Caller targets, versions, archives, components,
auth, targets, binds, variables, commands, paths, results, and retry controls
are not accepted.

Execution persists independently versioned owner-only generation-guarded
`deploy-scylla-vms.ansible-deploy-monitoring-stack-execution/v1` and
immutable-prefix
`deploy-scylla-vms.ansible-deploy-monitoring-stack-evidence/v1` records under
the canonical operation paths. It records retry-safe `prepared`, durably records
`started` immediately before its sole controlled call, and consumes the whole
immutable authorization without rewriting it. Strict success requires exact
target/archive/component/source/command/provenance parity,
installed-or-no-change state, disabled/inactive Docker, listen policy
`not-started`, and explicit absence of Docker installation/image pull,
Compose/auth/target generation, containers/service starts, public binds,
Manager registration, Scylla start, and secrets. Evidence is durable before
terminal success. A crash, timeout, interruption, unreachable/nonzero or
malformed result, semantic mismatch, post-call drift, or evidence-write
uncertainty after `started` is manual-recovery/no-retry and forbids rollback,
skip, or continuation. Exact `prepared` recovery is allowed only before
invocation; exact success re-entry is zero-process/zero-write. Reports and
evidence are bounded and redacted, local `show` validates but does not project
the records, and the journal, authorization, post-Manager reconciliation, prior
plans, CLI/public surface, and upstream-workaround inventory remain unchanged.

The implemented internal post-`monitoring-stack` reconciliation owner accepts
only canonical state-root/cluster/operation identity and the matching held
deploy lock. It reloads the exact verified infrastructure, historical mapping,
bootstrap/final-health, Manager/post-Manager, monitoring authorization/
execution/evidence, source/catalog, and unchanged `IN_PROGRESS/VERIFY` journal
chain. It requires consumed terminal success and one complete unique canonical
monitoring-target result with exact Scylla Monitoring 4.16.0 archive/component/
source/command provenance, installed-or-no-change state, disabled/inactive
Docker, listen policy `not-started`, and all Docker installation/image pull,
Compose/auth/target generation, container/service start, public bind, Manager
registration, Scylla start, and secret actions absent. Every incomplete,
uncertain, stale, conflicting, recovery-required, or drifted state fails closed.

It persists only immutable owner-only
`deploy-scylla-vms.ansible-deploy-post-monitoring-stack-reconciliation/v1` at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-monitoring-stack-reconciliation.json`.
The record proves the historical 21-position mapping unchanged, marks only the
exact mapped `monitoring-stack` instance evidence-bound succeeded, and evaluates
only the immediate next active mapped gate from exact current evidence. A
read-only gate may become `eligible`; a mutating gate may become only
`evidence-ready-authorization-required`. It never leapfrogs, generates targets/
auth/Compose, or infers stack health, readiness, or listeners. Exact reuse is
zero-write, conflicts never overwrite or adapt history, local `show` validates
the bounded redacted record, and every prior artifact plus the common VERIFY
journal remains unchanged. This owner does not authorize, execute, invoke a
process, finalize, add CLI/public wiring, or add an upstream-role workaround.

The implemented internal mapped `manager-agent` authorization owner accepts
only canonical state-root/cluster/operation identity, the matching held deploy
lock, and a normalized ordinary approval proof. It canonically reloads the
complete verified infrastructure, historical deploy mapping, storage/install/
configuration/bootstrap/final-health, Manager, monitoring-stack, source/
catalog, inventory/trust/readiness, and unchanged `IN_PROGRESS/VERIFY` journal
chain. It derives only active mapped position 16 and requires that scope to be
the complete current canonical Scylla stable-ID set with exact Ubuntu 24.04
architecture, successful current Scylla-install provenance, and the exact
Manager 3.12 `scylla-manager-agent` package/repository/authenticated signing-key/
source/variable/command intent. The agent remains disabled/inactive;
configuration, token, helper slice, server reachability, and service start stay
forbidden or not performed.

Interactive or PLAN-permitted `cli-yes` approval is required. Destructive and
narrow proofs are inapplicable, and approval never bypasses prerequisite,
identity, ordering, or drift gates. The owner persists only immutable owner-only
`deploy-scylla-vms.ansible-deploy-manager-agent-authorization/v1` at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-manager-agent-authorization.json`.
Exact reuse is zero-write; changed proof, scope, or provenance requires a new
operation. Authorization remains unconsumed and execution unavailable. Records
and reports retain only bounded schemas, digests, counts, enums, booleans, and
permitted stable IDs; local `show` validates the record. No process, execution,
reconciliation, journal transition, CLI/public wiring, or upstream-role
workaround is added.

The implemented internal mapped `manager-agent` execution owner accepts only
canonical state-root/cluster/operation identity, the matching held deploy lock,
the controlled runner, and the exact validated sibling Ansible executables and
toolchain. It canonically revalidates that full chain and exact unconsumed
authorization, then derives the ordered complete Scylla stable-ID scope and
invokes only the hash-checked `manager-agent` source serial-one, one target per
controlled call. Generation-guarded prepared/started/terminal execution and
immutable-prefix semantic evidence bind exact Manager 3.12 package,
repository, authenticated-key, source, variable, command, Ubuntu 24.04,
base-OS, and current Scylla-install provenance. The first durable `started`
attempt consumes the whole authorization without rewriting it; exact succeeded
prefixes alone may continue in immutable order.

Only strict installed/no-change evidence with the agent disabled/inactive and
configuration, token, helper-slice, server-reachability, and start behavior
absent or not performed can succeed. Every uncertain started outcome, malformed
or mismatched result, post-call drift, or persistence uncertainty is permanent
manual-recovery/no-retry; prepared recovery is safe only before invocation and
exact completed re-entry is zero-process/zero-write. The common VERIFY journal,
authorization, post-monitoring reconciliation, and historical plans remain
unchanged. Records/reports are bounded and redacted, local `show` validates both
companions, and no next-stage reconciliation, token/configuration/setup/server
contact, agent start, CLI/public wiring, or upstream-role workaround is added.

The implemented internal post-`manager-agent` reconciliation owner accepts only
canonical state-root/cluster/operation identity and the matching held deploy
lock. It reloads the exact verified infrastructure and historical deploy chain
through bootstrap/final health, Manager, monitoring, exact Manager-agent
authorization/execution/evidence, source/catalog, and the unchanged
`IN_PROGRESS/VERIFY` journal. It requires consumed terminal success plus one
complete unique ordered result per authorized Scylla stable ID with exact
Manager 3.12 package/repository/key/source/command provenance, installed-or-
no-change state, disabled/inactive service, and configuration, token, helper
slice, server reachability, and start behavior absent or not performed.

It persists only immutable owner-only
`deploy-scylla-vms.ansible-deploy-post-manager-agent-reconciliation/v1` at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-manager-agent-reconciliation.json`.
The record proves the historical 21-position mapping unchanged, marks only
mapped `manager-agent` evidence-bound succeeded with bounded changed/no-change
counts, and evaluates only the immediate next active mapped gate. Read-only work
may become `eligible`; mutating work may become only
`evidence-ready-authorization-required`. Exact reuse is zero-write, conflicts
fail closed, local `show` validates the bounded redacted record, and no process,
authorization, execution, journal change, token/configuration, Manager health
inference, CLI/public wiring, or upstream-role workaround is added.

The implemented internal mapped `monitoring-agent` authorization owner accepts
only canonical state-root/cluster/operation identity, the matching held deploy
lock, and a normalized ordinary approval proof. It canonically reloads the full
verified infrastructure and deploy chain through post-Manager-agent
reconciliation, exact current Scylla inventory/trust/readiness, successful
storage/install/configuration/bootstrap/final health, source/catalog, and the
unchanged `IN_PROGRESS/VERIFY` journal. It derives only active mapped position
17, with scope equal to the complete canonical Scylla stable-ID set, exact
Ubuntu 24.04 architecture and Scylla-install provenance, and exact ScyllaDB
2026.2 `scylla-node-exporter` package/repository/authenticated-key/source/
variable/command intent. The exporter remains disabled/inactive with listen
policy `not-started`; configuration, process-exporter, stack/target generation,
Manager registration, exporter/Scylla startup, listeners, and secrets remain
forbidden or not performed.

Interactive or PLAN-permitted `cli-yes` approval is required. Destructive and
narrow proofs are inapplicable and approval cannot bypass prerequisite,
identity, no-listen, ordering, or drift gates. The owner persists only immutable
owner-only
`deploy-scylla-vms.ansible-deploy-monitoring-agent-authorization/v1` at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-monitoring-agent-authorization.json`.
Exact reuse is zero-write; changed proof, scope, or provenance requires a new
operation. Authorization remains unconsumed and execution unavailable. Records
and reports are bounded/redacted, local `show` validates the record, and no
process, execution, reconciliation, journal transition, CLI/public wiring, or
upstream-role workaround is added.

The implemented internal mapped `monitoring-agent` execution owner accepts only
canonical state-root/cluster/operation identity, the matching held deploy lock,
the controlled runner, and the exact validated sibling Ansible executables and
toolchain. It canonically revalidates the full chain and exact unconsumed
authorization, derives the ordered complete Scylla stable-ID scope, and invokes
only the hash-checked `monitoring-agent` source serial-one with one target per
controlled call. Generation-guarded prepared/started/terminal execution and
immutable-prefix semantic evidence bind the exact ScyllaDB 2026.2 node-exporter
package, repository, authenticated-key, source, variable, command, Ubuntu 24.04,
base-OS, and current Scylla-install provenance. The first durable `started`
attempt consumes the whole authorization without rewriting it; exact succeeded
prefixes alone may continue in immutable order.

Only strict installed/no-change evidence with the exporter disabled/inactive,
listen policy `not-started`, and configuration, process-exporter, stack,
targets, Manager registration, exporter/Scylla startup, listeners, and secrets
absent or not performed can succeed. Every uncertain started outcome, malformed
or mismatched result, post-call drift, or persistence uncertainty is permanent
manual-recovery/no-retry; prepared recovery is safe only before invocation and
exact completed re-entry is zero-process/zero-write. The common VERIFY journal,
authorization, post-Manager-agent reconciliation, and historical plans remain
unchanged. Records/reports are bounded and redacted, local `show` validates both
companions, and no next-stage reconciliation, target/configuration generation,
listener or service start, CLI/public wiring, or upstream-role workaround is
added.

The implemented internal post-`monitoring-agent` reconciliation owner accepts
only canonical state-root/cluster/operation identity and the matching held
deploy lock. It canonically reloads the exact verified infrastructure and
historical deploy chain through bootstrap/final health, Manager, monitoring,
exact Monitoring-agent authorization/execution/evidence, source/catalog, and
the unchanged `IN_PROGRESS/VERIFY` journal. It requires consumed terminal
success plus one complete unique ordered result per authorized Scylla stable ID
with exact ScyllaDB 2026.2 exporter package/repository/key/source/command
provenance, installed-or-no-change state, disabled/inactive service, listen
policy `not-started`, and configuration, process-exporter, stack, targets,
registration, startup, listener, and secret behavior absent or not performed.

It persists only immutable owner-only
`deploy-scylla-vms.ansible-deploy-post-monitoring-agent-reconciliation/v1` at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-monitoring-agent-reconciliation.json`.
The record proves the historical 21-position mapping unchanged, marks only
mapped `monitoring-agent` evidence-bound succeeded with bounded changed/
no-change counts, and evaluates only the immediate next active mapped gate.
Read-only work may become `eligible`; mutating work may become only
`evidence-ready-authorization-required`. Exact reuse is zero-write, conflicts
fail closed, local `show` validates the bounded redacted record, and no process,
authorization, execution, journal change, target generation, exporter/stack
health inference, CLI/public wiring, or upstream-role workaround is added.

The implemented internal mapped `monitoring-targets` authorization owner accepts
only canonical state-root/cluster/operation identity, the matching held deploy
lock, and one normalized ordinary approval proof. It recursively reloads the
exact chain through post-`monitoring-agent` reconciliation, reproduces that
immutable record from its current context and `created_at`, and requires only
mapping position 18 `monitoring-targets` to be
`evidence-ready-authorization-required` for the single canonical monitoring
stable ID. Generic authorization, ambiguous same-family records, execution,
evidence, reconciliation, and later-stage history are refused.

The owner derives exact Ubuntu 24.04 architecture and successful current
base-OS, Scylla Monitoring 4.16.0 stack, Manager-server, Manager-agent, and
Monitoring-agent evidence. It reconstructs current typed monitoring-stack
evidence from the canonical semantic entry and current deterministic archive
payload, then rebuilds the official monitoring-targets payload. The payload
must contain exactly four official target intents, one Manager target, and the
complete current Scylla identity set for Scylla, node-exporter, and
Manager-agent targets. The existing builder enforces canonical RFC 1918
identities. Authorization persists only bounded counts, enums, booleans,
permitted stable IDs, and file-set/content, target-set, identity, evidence,
variable, anchored-command, source, catalog, proof, and record digests. File
names, paths, contents, labels, addresses, ports, provider IDs, routes,
configuration/auth values, commands, variables, environment, prompts/free
text, credentials, and secrets remain absent.

Ordinary interactive or PLAN-permitted `cli-yes` approval is required;
destructive flags/scope and narrow consent are refused. The immutable owner-only
`deploy-scylla-vms.ansible-deploy-monitoring-targets-authorization/v1` record is
stored only at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-monitoring-targets-authorization.json`.
Exact same-proof reuse is zero-write; changed proof, target set, intent, source,
catalog, evidence, or provenance requires a new operation. Authorization stays
unconsumed, execution unavailable, finalization not started, public workflow
unavailable, and the VERIFY journal and all prior artifacts byte-for-byte
unchanged. Local `show` validates the record. This slice does not write target
files, invoke Ansible, create execution/reconciliation state, start exporters
or the stack, add CLI/public wiring, or introduce an upstream workaround.

The implemented internal mapped `monitoring-targets` execution owner accepts
only canonical state-root/cluster/operation identity, the matching held deploy
lock, a controlled runner, and the exact validated sibling Ansible
executables/toolchain. It canonically reloads the complete chain through exact
post-Monitoring-agent reconciliation and immutable unconsumed authorization,
rebuilds the deterministic official four-file intent from current RFC 1918
Manager/Scylla identities, and derives the single monitoring target, variables,
hash-checked source, and anchored command without caller-owned execution input.

Generation-guarded owner-only execution and immutable-prefix semantic evidence
record retry-safe `prepared` before effects and durable authorization-consuming
`started` immediately before the sole serial-one call. Success requires strict
generated/no-change target, Monitoring 4.16.0, file-set/content, bounded target
counts, identity-set, source/command/intent/provenance, `not-started` listen,
and `not-performed` scrape evidence; Docker, stack/container/exporter/Manager/
Scylla starts, auth, public binds, Compose, and secrets remain forbidden. Any
uncertain started outcome, malformed or mismatched result, post-call drift, or
persistence uncertainty is permanent manual-recovery/no-retry. Prepared
recovery is safe only before invocation and exact completed re-entry is
zero-process/zero-write. The VERIFY journal, authorization, reconciliation, and
historical plans remain unchanged. Records/reports are bounded and redacted,
local `show` validates both companions, and no next-stage reconciliation,
service start, scrape test, UI exposure, CLI/public wiring, or upstream-role
workaround is added.

The implemented internal post-`monitoring-targets` reconciliation owner accepts
only canonical state-root/cluster/operation identity and the matching held
deploy lock. It canonically reloads the full verified infrastructure and
historical deploy chain through bootstrap/final health, Manager, monitoring,
exact monitoring-targets authorization/execution/evidence, source/catalog, and
the unchanged `IN_PROGRESS/VERIFY` journal. It requires consumed terminal
success plus one complete unique Monitoring 4.16.0 generated-or-no-change
result for the canonical monitoring host with exact four-file file-set,
content, identity, source, command, intent, and provenance evidence. Listen
policy remains `not-started`, scrape readiness remains `not-performed`, and
Docker, stack/container/exporter/Manager/Scylla starts, auth, public binds,
Compose, and secrets remain absent.

It persists only immutable owner-only
`deploy-scylla-vms.ansible-deploy-post-monitoring-targets-reconciliation/v1`
at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-monitoring-targets-reconciliation.json`.
The record proves the historical 21-position mapping unchanged, marks only
mapped `monitoring-targets` evidence-bound succeeded, and evaluates only
immediate sensitive `manager-tasks`. That step retains its exact blockers
because `explicit-task-action` remains unmodeled and the packaged source is a
validation-only refusal contract while Manager is inactive, unregistered, and
without a configured backend. No default action, backup/repair readiness,
`sctool` call, service start/unmask, backend configuration, or registration is
inferred. Exact reuse is zero-write, conflicts fail closed, local `show`
validates the bounded redacted record, and no process, authorization, execution,
journal change, finalization, CLI/public wiring, or upstream-role workaround is
added.

The implemented internal Manager-activation planning bridge accepts only the
canonical state root, cluster name, operation UUID, and matching already-held
deploy lock. It reloads and reproduces the complete exact chain through
post-`monitoring-targets` reconciliation and current Manager-server/Manager-agent
install evidence, inventory, trust, readiness, source, catalog, and unchanged
`IN_PROGRESS/VERIFY` journal. It derives the one canonical Manager stable ID and
the complete canonical Scylla Manager-agent scope without accepting actions,
backend/registration/task definitions, targets, commands, variables, paths, or
free text.

It persists separate immutable owner-only
`deploy-scylla-vms.ansible-deploy-manager-activation-context/v1` then
`deploy-scylla-vms.ansible-deploy-manager-activation-plan/v1` companions at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-manager-activation-{context,plan}.json`.
The historical 21-position mapping and every prior reconciliation remain
unchanged. The separate plan records four ordered, non-executable boundaries:
mutating backend configuration, mutating Manager service activation/readiness,
sensitive cluster-registration/auth-token handoff, and then sensitive mapped
`manager-tasks` action/context. The first three boundaries are explicitly
source-unavailable; all four are authorization-required, evidence-required,
blocked, and not-performed. The existing `manager-tasks` source is
source-available but validation-only. Deploy's `explicit-task-action` condition
does not identify a deterministic action, so the bridge persists
`manager-tasks-action-unmodeled` and does not substitute the source contract's
default `inspect`.

Both records are built fully in memory before context-first persistence. Exact
context-only recovery and exact zero-write reuse are allowed; conflicts,
tamper, drift, ambiguous artifacts, or changed provenance fail closed. The
records and report retain only bounded schemas/digests/counts/enums/booleans
and permitted stable IDs, while the VERIFY journal remains unchanged and no
authorization, execution, runner, finalization, CLI/public wiring, or upstream
workaround is added.

The implemented internal Manager backend-configuration planning owner accepts
only canonical state-root/cluster/operation identity and the matching held
deploy lock. It canonically reproduces the Manager-activation context and plan,
post-`monitoring-targets` reconciliation, Manager-server and complete
Manager-agent install evidence, final complete-set Scylla health/topology,
observation/inventory/trust/readiness, packaged source/catalog, and unchanged
`IN_PROGRESS/VERIFY` journal. It persists separate immutable owner-only
`deploy-scylla-vms.ansible-deploy-manager-backend-configuration-context/v2`
then
`deploy-scylla-vms.ansible-deploy-manager-backend-configuration-plan/v2`
companions at
`<cluster-root>/operations/<operation-uuid>.ansible-deploy-manager-backend-configuration-{context,plan}.json`.
Both are built in memory first; exact context-only recovery and zero-write
reuse are allowed, while drift, tamper, conflicts, ambiguous later artifacts,
or changed provenance fail closed.

The versioned design selects `local-one-node` on the Manager VM, forbids the
managed data cluster as backend, forbids CQL network ingress, fixes a
loopback-only policy with default CQL port 9042 and ScyllaDB 2026.2
compatibility, and requires no backend credentials or TLS secrets for this
local loopback v1. Only the typed backend-mode gate is newly passed. Backend
package availability, storage/tuning/capacity suitability, setup behavior,
identity/topology/health, exact configuration binding, schema/keyspace policy,
recovery semantics, and the mutating source remain typed unknown/blockers.
Future Manager-agent token intake remains environment-only and is not weakened.

The exact Manager target, install evidence, masked/inactive service
precondition, final Scylla health/topology, canonical provenance, and source
catalog remain passed gates. The read-only `manager-backend-preflight` source
can collect bounded host planning evidence but cannot satisfy the mutating
configuration boundary. The install-only `manager-server` source cannot write
configuration and validation-only `manager-tasks` cannot configure a backend.
The sole mutating backend step therefore remains source-unavailable,
blocked-before-authorization, and not-performed. Records/reports contain only
schemas, digests, bounded counts/enums/booleans, and permitted stable IDs; they
omit addresses, provider IDs, backend/configuration/auth/TLS/token/credential
values, ports, commands, variables, paths, prompts, and secret values. The
historical 21-position mapping and VERIFY journal remain unchanged.

The implemented operation-bound Manager backend-preflight owner accepts only
canonical cluster/operation identity, the matching held deploy lock, controlled
runner, and exact sibling Ansible executable/toolchain dependency. It
revalidates the full immutable chain through the local-one-node backend plan
and current controller files, derives the exact Manager target and fixed
read-only intent internally, and invokes only the hash-checked
`manager-backend-preflight` source under its exact-one-target, serial-one,
check-mode-safe policy. It durably records `started` before the sole call and
requires strict semantic target, host, source, command, and provenance parity;
process exit zero alone is insufficient.

Execution and semantic evidence are independently versioned, owner-only,
operation-bound records. Evidence retains only bounded capacities, approved
mount counts/status, fixed package/service/configuration/schema/reboot/loopback
states, explicit not-performed actions, blockers, and digests. Started
uncertainty, timeout, interruption, nonzero/unreachable/malformed results,
semantic mismatch, drift, or post-call persistence failure permanently require
manual recovery and forbid retry. Exact completed re-entry is
zero-process/zero-write, conflicting prefixes fail closed, and the common
VERIFY journal and every prior record remain unchanged.

The immutable reconciliation requires exact terminal execution success and
complete current semantic evidence. It evaluates only the later local-backend
installation-planning boundary and preserves package availability,
storage/tuning suitability, exact capacity policy, setup behavior,
schema/keyspace policy, recovery, and mutating-source requirements as explicit
unknown or blocked gates. Backend operational readiness remains
`not-performed`, mutation authorization unavailable, and mutation execution not
started. That evidence is consumed only by the separate local-backend
installation-planning owner below. The preflight boundary itself does not
authorize mutation. Only the separately modeled package-install authorization
and execution owners below are available; result reconciliation,
configuration, setup, schema creation, service activation, and recovery remain
absent until their distinct source/result/recovery contracts are approved.
Later Manager service, registration/token, and task owners remain ordered
behind them.

The implemented internal Manager local-backend installation-planning owner
accepts only canonical cluster/operation identity and the matching held deploy
lock. It revalidates the complete chain through exact backend-preflight
execution/evidence/reconciliation and persists immutable owner-only
`deploy-scylla-vms.ansible-deploy-manager-backend-installation-context/v1`
then `deploy-scylla-vms.ansible-deploy-manager-backend-installation-plan/v1`
companions under the operation directory. Both records are built in memory;
context-only recovery and exact zero-write reuse are allowed, while tamper,
drift, ambiguous history, or changed provenance fails closed. The historical
21-position mapping and `IN_PROGRESS/VERIFY` journal remain unchanged.

Planning safely reuses only exact Ubuntu 24.04/architecture and authenticated
ScyllaDB 2026.2 repository/key references. It binds one observed,
provider-identified Manager Block Volume when present but never persists its
provider identity and never falls back to root/boot storage or generic free
space. Missing or unidentifiable dedicated storage records
`dedicated-backend-storage-unmodeled`. Exact capacity thresholds, Manager-role
package set, storage layout/mutation policy, tuning, service order,
configuration ownership, keyspace/RF/schema, recovery, and
`scyllamgr_setup` behavior remain typed blockers.

The plan keeps package install, dedicated-storage allocation, storage
preflight/prepare/postcheck, local Scylla configuration/tuning, one-node
bootstrap/start/health, Manager backend-file configuration, and schema/keyspace
creation/verification as nine separate ordered, not-performed boundaries. The
first package boundary now binds the separately versioned
`manager-backend-local-install` source and becomes
`evidence-ready-authorization-required` only when every exact prerequisite and
dedicated-storage gate passes. At publication the remaining eight sources are
unavailable; the immutable installation plan is not rewritten when the
separate Manager storage discovery source is introduced later. Existing
Scylla-role storage,
configure, and bootstrap owners are reference-only and cannot be reused across
their target/provenance contracts. The package
source revalidates that exact immutable chain and identified dedicated-storage
status, installs the exact authenticated ScyllaDB 2026.2 package set on the
Manager VM, and leaves `scylla-server` masked/inactive. Strict
`deploy-scylla-vms.ansible-manager-backend-local-install/v1` evidence binds
package/repository/key/source/command provenance and records every setup,
storage, tuning, configuration, CQL/schema, Manager, token, registration/task,
and service-start action false or not-performed. Check mode is non-predictive.

The implemented operation-bound package-install authorization owner accepts
only canonical cluster/operation identity, the matching held deploy lock, and a
normalized ordinary interactive or PLAN-permitted `cli-yes` proof. It
reproduces the current installation plan against the complete preflight,
Manager/base-OS, observation/inventory/trust/readiness, source, catalog,
package, repository, and authenticated signing-key chain. Stale immutable
plans, changed proof/scope/provenance, dedicated-storage ambiguity, and every
drift or tamper fail closed and require a new operation. It persists only the
immutable owner-only
`deploy-scylla-vms.ansible-deploy-manager-backend-local-install-authorization/v1`
checkpoint, with exact zero-write reuse, authorization unconsumed, execution
unavailable, and the `IN_PROGRESS/VERIFY` journal and prior records unchanged.
Destructive and narrow proofs are refused; protected values and executable
inputs remain absent.

The implemented operation-bound package-install execution owner accepts only
canonical cluster/operation identity, the matching held deploy lock, a
controlled runner, and exact validated sibling Ansible executables/toolchain.
It reloads the complete authorization chain and derives the sole Manager
target, Ubuntu 24.04 architecture, exact authenticated ScyllaDB 2026.2 package
intent, dedicated-storage binding, source, variables, and anchored command.
Generation-guarded execution records retry-safe `prepared` and durable
authorization-consuming `started`; immutable-prefix semantic evidence must
prove installed/no-change, masked/inactive Scylla, and every setup, storage,
tuning, configuration, schema/CQL, Manager, registration/task, token, and
service-start action absent. Any uncertainty after `started` is permanent
manual-recovery/no-retry; exact completed re-entry is zero-process/zero-write.
The journal, authorization, and plans remain unchanged at
`IN_PROGRESS/VERIFY`, and local `show` validates both redacted companions.

The implemented post-package-install reconciliation owner accepts only
canonical cluster/operation identity and the matching held deploy lock. It
reloads and reproduces the full local-one-node policy, preflight, installation
plan, package authorization/execution/evidence, Manager/base-OS, current local
state, source/catalog, and unchanged VERIFY-journal chain. Only exact terminal
success with consumed execution authorization, complete installed/no-change
semantic evidence, masked/inactive Scylla, and every forbidden action absent is
accepted. Prepared, started, failed, uncertain, incomplete, stale, conflicting,
or drifted histories fail closed.

It persists immutable owner-only
`deploy-scylla-vms.ansible-deploy-post-manager-backend-local-install-reconciliation/v1`
at the canonical operation path, marks only `package-install` evidence-bound
succeeded, and preserves every original boundary/order/identity digest. It
derives and evaluates only the immediate next boundary from the immutable plan:
`local-storage-allocation` remains blocked because its Manager-local
source/contract and exact capacity policy are unapproved and the existing
Scylla-role storage owner is contract-incompatible. Capacity, tuning, setup,
configuration, schema, and recovery gates remain unknown or blocked; no later
boundary advances. Exact re-entry is zero-write, local `show` validates the
companion, prior records and the journal remain unchanged, and no process,
authorization, mutation, or CLI/public wiring is added. That reconciliation
remains immutable and blocked.

The implemented Manager-local storage allocation/discovery planner adds
separate immutable context and plan records without rewriting that
reconciliation or the nine-boundary installation plan. It revalidates the
complete chain and derives only one exact dedicated Manager Block Volume from
matching desired, Terraform input, observed storage-manifest, inventory, and
readiness identities. Root/boot fallback, local NVMe, arbitrary attachments,
path/order selection, and shared Scylla-role storage are forbidden. Missing,
ambiguous, or path-only allocation identity creates no discovery scope.
Requested/observed GiB and count/backend facts remain bounded planning
evidence; capacity policy is `unknown` and adequacy is `not-evaluated`.

The distinct hash-checked `manager-backend-storage-discover` source is
Manager-only, exact-one-target, serial-one, fatal, check-mode-safe, and
strictly read-only. It matches bounded Linux block/mount/signature/ownership
facts against the exact Terraform manifest through non-path identities and
returns only redacted enums/counts plus hashed device/topology/manifest/
provenance evidence. It performs no write, wipe, partition, RAID, filesystem,
mount, fstab, configuration, service, or CQL action. Its operation-bound
execution/evidence and reconciliation owners now preserve strict no-retry
started semantics and leave capacity adequacy unknown.

The subsequent immutable storage-preflight planner binds that successful
discovery to one whole dedicated Block Volume, XFS, fixed `/var/lib/scylla`
ownership, fstab/mount intent, and a Manager-local one-node marker. Requested,
observed, and discovered GiB equality proves policy conformance only; capacity
sufficiency remains unknown. The distinct read-only
`manager-backend-storage-preflight` source classifies only `owned-noop`,
`prepare-required`, or `blocked`; foreign signatures block while reporting
wipe-required separately from future authorization. It emits only bounded
redacted digest evidence. Its operation-bound execution owner now derives and
invokes the exact hash-checked read-only scope with durable started/no-retry
semantics and immutable semantic evidence. Reconciliation marks preflight
succeeded, leaves `owned-noop` not-required and blocked evidence blocked,
derives only the exact `prepare-required` scope, and binds wipe-required scope
separately. Capacity sufficiency remains unknown, so the next Manager-local
storage preparation boundary remains blocked pending separately reviewed
capacity policy and source. No authorization, mutation, postcheck, journal
transition, or CLI/public wiring exists.

**Operation procedure:**

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
  `ansible/playbooks/scylla-install.yml` and
  `ansible/playbooks/scylla-configure.yml`, limited to the same ID.
- **4.** `ansible/playbooks/scylla-bootstrap.yml` limited to that same ID,
  followed by `ansible/playbooks/scylla-health.yml` on the cluster.
- **5.** `ansible/playbooks/manager-agent.yml` and
  `ansible/playbooks/monitoring-agent.yml` limited to the healthy new node,
  followed by `ansible/playbooks/scylla-cleanup.yml` serially on the computed
  eligible old nodes.
- **6.** `ansible/playbooks/monitoring-targets.yml`,
  `ansible/playbooks/manager-tasks.yml` with validate/resume action, and
  `ansible/playbooks/evidence-collect.yml`.

**Operation procedure:**

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
  `ansible/playbooks/scylla-install.yml` and
  `ansible/playbooks/scylla-configure.yml` on that same batch.
- **3.** `ansible/playbooks/scylla-bootstrap.yml` for the batch, then
  `ansible/playbooks/scylla-health.yml` for the full cluster before Python plans
  another batch, followed by `ansible/playbooks/manager-agent.yml` and
  `ansible/playbooks/monitoring-agent.yml` limited to the healthy new nodes.
- **4.** After all additions, `ansible/playbooks/scylla-cleanup.yml` serially on
  the documented Python-computed host set, then
  `ansible/playbooks/monitoring-targets.yml`,
  `ansible/playbooks/manager-tasks.yml` with validate/resume action, and
  `ansible/playbooks/evidence-collect.yml`.

**Operation procedure:**

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
| `--reason` | Non-empty text, at most 500 characters | Required; no default | No | Journal operator replacement rationale. |
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
  `ansible/playbooks/scylla-install.yml` and
  `ansible/playbooks/scylla-configure.yml` on that same generation.
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

**Operation procedure:**

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
   ownership, then configure the replacement host with the exact same ScyllaDB
   2026.2 patch release, cluster identity, datacenter, rack, and seeds. With the
   service masked/inactive and data empty, atomically add only
   `replace_node_first_boot: <dead-host-id>` to `/etc/scylla/scylla.yaml`;
   obsolete `replace_address*` keys are forbidden. Never run `removenode`
   before replacement. Unmask/start once, monitor bounded `nodetool gossipinfo`
   during streaming, then `nodetool status`, `netstats`, and schema evidence
   from healthy survivors until the new Host ID is UN and the old Host ID is
   absent. Retain the first-boot key after success as permitted by the official
   procedure. Wait for streaming, token ownership, schema, and ring-health gates;
   do not run another topology operation concurrently. Perform post-replacement
   repair unless strict validated Repair Based Node Operations evidence proves
   the replacement operation complete without it. The replacement source does
   not execute repair and the operation cannot finalize until later repair or
   Manager evidence satisfies this gate. Follow the
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

**Operation procedure:**

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

**Operation procedure:**

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

**Operation procedure:**

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
  `ansible/playbooks/scylla-install.yml`,
  `ansible/playbooks/scylla-configure.yml`,
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

**Operation procedure:**

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
  `ansible/playbooks/scylla-install.yml`,
  `ansible/playbooks/manager-agent.yml`, or
  `ansible/playbooks/monitoring-agent.yml`; agent/package drift belongs to an
  explicit `redeploy` scope.

**Operation procedure:**

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
  `ansible/playbooks/scylla-install.yml`,
  `ansible/playbooks/scylla-configure.yml`,
  `ansible/playbooks/scylla-replace-dead.yml`,
  `ansible/playbooks/manager-agent.yml`, and
  `ansible/playbooks/monitoring-agent.yml`, rather than generic reprovision.
- **4.** `ansible/playbooks/os-upgrade-postcheck.yml`, then
  `ansible/playbooks/scylla-health.yml` where applicable, before Python advances
  to another host. Never run both in-place and reprovision variants for one host.
- **5.** After all hosts, `ansible/playbooks/manager-tasks.yml` with
  validate/resume action and `ansible/playbooks/evidence-collect.yml`.

**Operation procedure:**

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

The currently packaged `os-upgrade-preflight` implements step 2 only as a
strict blocked validation report. The packaged `os-upgrade-in-place` step 3a
accepts only exact current, explicitly rolling-eligible preflight provenance
and returns strict blocked/not-performed evidence; it performs no upgrade.
The packaged `os-reprovision-prepare` step 3b likewise validates immutable
replacement intent but returns strict blocked/not-performed evidence without
OCI, Terraform, VM, storage, service, membership, configuration, or reboot
mutation. No approved target transition or provider-replacement orchestration
exists, so neither step 3 path is executable and no public `upgrade-os`
orchestration invokes these sources.

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
| `--destination-check` | Repeatable `ROLE=PORT`; `scylla` permits `7000`, `7001`, `9042`, or `9142`, `manager` permits `5080`, and `monitoring` permits `3000` or `9090` | Empty list means jump-host SSH only | No | Add policy-approved private TCP reachability checks without arbitrary hosts. |
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

**Operation procedure:**

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

**Implemented guarded jump-host slice (26.9.1):** `check-jump-hosts` now loads
and reconciles existing canonical cluster, observation, inventory, trust,
`known_hosts`, SSH route, and Ansible configuration evidence under the
non-mutating cluster read lock. It runs `inventory-preflight` first and then
`connectivity-check` with exact selected jump-host stable-ID limits, bounded
aggregate/per-connection timeouts, mandatory host-key checking, and no provider
or Terraform call. Human output and the independent
`deploy-scylla-vms.check-jump-hosts/v2` JSON schema expose only allowlisted
provenance, route/trust summaries, performed/not-performed checks, and per-jump
status; addresses, key blobs, private-key paths, credentials, and raw Ansible
output remain omitted. Partial/full failure, timeout, and invalid evidence render
before returning Ansible exit `7`. Zero persisted jump hosts return a truthful
no-target success without invoking Ansible.

**Implemented destination TCP slice (26.9.1):** `--destination-check ROLE=PORT`
now resolves only the allowlisted service ports above to validated RFC 1918
inventory hosts whose typed ProxyJump route is assigned to each selected jump.
No address, DNS name, URL, protocol override, port range, public endpoint,
self-target, or unbounded list is accepted. `--depth route` deterministically
selects the first stable logical target per role and jump;
`--depth all-targets` selects all assigned pairs up to the fixed 64-pair bound.
The existing `connectivity-check` playbook preserves SSH ping and performs each
TCP connection from its selected jump with read-only
`ansible.builtin.wait_for`, bounded per-probe and aggregate timeouts, and
sanitized pair evidence. Human output and the strict
`deploy-scylla-vms.check-jump-hosts/v2` JSON report every pair as passed, failed,
or not performed without addresses. Partial probe failures render before exit
`7`. An absent `--destination-check` preserves jump-only behavior;
`all-targets` without a TCP check remains unavailable because private-target
SSH checking is not implemented. Unlike the future procedure above, this
read-only slice does not write an operation journal.

### Show

**CLI flags**

Applies `core`. It conditionally accepts `oci-context`: `--oci-region` and
`--oci-compartment-id` are persisted-identity assertions when supplied, while
`--oci-auth-mode` and its environment-only credential set are required only when
`--live provider` or `--live all` performs provider API reads. Default execution
does not require cloud credentials. It rejects `mutate`, `destructive`,
`network`, `topology`, `shapes`, both storage groups, `--dry-run`, `--plan`,
`--yes`, and every confirmation flag because it cannot alter infrastructure,
state, inventory, or cluster configuration.

| Flag | Type / accepted values | Default or required behavior | Environment | Purpose |
| --- | --- | --- | --- | --- |
| `--section` | Repeatable enum: `summary`, `topology`, `hosts`, `storage`, `services`, `freshness`, `operations`, `drift`, `health`, or `all` | Empty list means `all` | No | Select report sections without changing source validation. |
| `--node-id` | Repeatable existing stable logical host ID | Empty list means all persisted hosts | No | Filter host-scoped rows after identity reconciliation. |
| `--live` | Repeatable enum: `provider`, `connectivity`, `health`, or `all` | Empty list; perform no provider, SSH, Ansible, or Scylla live checks | No | Request bounded read-only validation sources explicitly. |
| `--include-addresses` | Sensitive-output action boolean | `false` | No | Include exact private/public addresses and route endpoints in stdout; never relax any other redaction. |
| `--fail-on` | Repeatable enum: `stale`, `drift`, `conflict`, `unhealthy`, `unknown`, or `none` | `conflict` | No | Render the report, then map selected findings to stable nonzero exit codes. |
| `--live-timeout-seconds` | Positive integer seconds | `300` | `DEPLOY_SCYLLA_VMS_SHOW_LIVE_TIMEOUT_SECONDS` | Bound the aggregate explicitly requested live-check phase. |

`all` cannot be combined with another value in the same repeatable option.
`--fail-on none` cannot be combined with another failure class and does not
suppress malformed CLI, unsafe path/permission, missing cluster identity,
invalid Terraform/output schemas, lock failures, or failure to execute an
explicitly requested live check. A selected section never suppresses validation
of the underlying cluster identity. Unknown `--node-id` values are CLI errors;
filters never select by list index, IP address, or provider ID.

**Implemented local subset (26.9.1):** `show` reads schema-v2 cluster metadata,
the embedded desired `ClusterSpec`, and validated operation journals only. It
uses an exclusive directory-backed read lock that creates and changes no file;
shared locking remains deferred. Human and `deploy-scylla-vms.show/v1` JSON
rendering, sections, stable-ID filters, address omission, provenance/freshness
labels, and locally decidable `--fail-on` findings are implemented. Terraform
output, inventory, provider, connectivity, and health adapters are absent and
are reported as unavailable, not performed, or unknown. Every explicit
`--live` request is rejected as not implemented before credentials or external
access; `--include-addresses` cannot emit values until a strict local address
manifest exists.

Human-readable output is the default. The `core` `--json` flag emits the stable
versioned `deploy-scylla-vms.show/v1` object with deterministic key/host order,
the selected sections, report generation time, source digests/timestamps, and
finding/exit-status fields. YAML is not supported. Exact addresses are omitted
from both formats unless `--include-addresses` is present. That flag classifies
the invocation as **read-only with sensitive output**, remains CLI-only, writes
addresses only to stdout, and never includes them in ordinary logs or operation
journals; operators are responsible for protecting redirected stdout.

**Required Ansible playbooks (execution order)**

- **Default.** No Ansible playbook runs. Persisted metadata and canonical local
  Terraform state/output are sufficient for the default report.
- **1.** When `--live connectivity`, `--live health`, or `--live all` is
  requested, run `ansible/playbooks/inventory-preflight.yml` read-only against
  an in-memory validated inventory projection.
- **2.** For `connectivity` or `all`, run
  `ansible/playbooks/connectivity-check.yml` with explicit stable-ID limits and
  the remaining aggregate timeout.
- **3.** For `health` or `all`, run
  `ansible/playbooks/scylla-health.yml` against the filtered Scylla hosts and
  required cluster peers, then `ansible/playbooks/evidence-collect.yml` with its
  health-summary action and explicit limits for relevant Manager, monitoring,
  and jump-host service status. A provider-only live check uses no Ansible
  playbook.

These playbooks collect facts only and must report partial/unreachable results;
no configuration, package, storage, topology, monitoring-target, Manager-task,
or operation-journal-mutating playbook is permitted.

**Operation procedure:**

1. Parse the global-before-subcommand CLI, resolve the validated cluster name
   and canonical cluster root, classify exact-address disclosure separately,
   and reject every mutation, arbitrary target, or unsupported format option.
2. Acquire a shared/read lock when supported, otherwise the normal cluster lock,
   within the requested lock timeout. Validate that the state root and cluster
   root are canonical, owner-controlled, non-symlinked, and permission-safe;
   return the existing lock or unsafe-path exit rather than reading around an
   active incompatible operation. Follow the plan's
   [Terraform state security guidance](https://developer.hashicorp.com/terraform/language/state/sensitive-data)
   even though the rendered projection is redacted.
3. Load persisted cluster metadata, desired topology, stable host identities,
   storage policies/manifests, prepared-storage records, canonical generated
   inventory metadata, operation journals, and the last successful operation/
   checkpoint. Missing cluster identity or structurally invalid ownership/schema
   is fatal; missing optional evidence becomes explicitly unavailable only when
   safe to report.
4. By default, execute only `terraform output -json` against the canonical local
   backend/state and existing `TF_DATA_DIR`; do not run `init`, refresh, plan,
   apply, import, state mutation, or save a refresh-only plan. Strictly validate
   the versioned output schema and read the existing state snapshot without
   rewriting canonical state or inventory. Use Terraform's
   [`output -json` contract](https://developer.hashicorp.com/terraform/cli/commands/output),
   [machine-readable JSON format](https://developer.hashicorp.com/terraform/internals/json-format),
   and [state model](https://developer.hashicorp.com/terraform/language/state).
5. Reconcile in memory. For each field retain separate desired/persisted,
   Terraform-observed, and live-validated values plus source digest/time. Mark
   cached evidence as `fresh`, `stale`, `unknown`, `unavailable`, or
   `not-performed`; a check omitted by the operator is `not-performed`, never
   healthy, and old inventory/provider/health data is never presented as
   current. Report identity, membership, topology, storage, inventory, manifest,
   and operation-checkpoint conflicts without choosing a winner or rewriting
   files.
6. If requested, perform only bounded reads after local reconciliation:
   `provider` queries the managed resource identities through provider APIs;
   `connectivity` validates the inventory-derived SSH/bastion routes; and
   `health` validates Scylla membership/datacenter/rack/ring and relevant
   Manager/monitor status. Use current
   [OCI provider data/resource contracts](https://registry.terraform.io/providers/oracle/oci/latest/docs),
   the [Ansible inventory model](https://docs.ansible.com/ansible/latest/inventory_guide/index.html),
   and [Ansible playbook/check-mode limits](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_checkmode.html).
   Never refresh Terraform state as a side effect. Preserve successful facts and
   report each timeout, unreachable host, authentication failure, or unsupported
   check independently instead of discarding the partial report.
7. Apply section and stable-ID filters only after reconciliation, then project
   cluster identity, provider/region, desired/observed topology, roles/zones,
   Scylla datacenter/rack, provider IDs, shapes, storage backend/capacity/
   ephemeral status, service/jump-host summaries, freshness, last successful
   operation/checkpoint, drift/conflicts, and health when known. By default,
   replace exact IPs/endpoints with address-present, private/public exposure,
   and stable bastion-route summaries. With `--include-addresses`, label each
   exact value as private, public, or route endpoint while still excluding
   secrets, credential paths/material, raw environment values, sensitive
   Terraform variables, command lines, and unredacted provider/Ansible payloads.
8. Render deterministic human output or the versioned JSON schema to stdout.
   Emit the report before applying `--fail-on`: freshness/drift/conflict findings
   map to exit `5`, selected unhealthy findings to `8`, malformed input to `2`,
   lock failure to `4`, and inability to perform an explicitly requested auth/
   provider/connectivity check to `3`. Unknown/stale/not-performed facts render
   successfully with exit `0` unless selected by `--fail-on`; structural
   identity/schema/permission failures remain nonzero regardless of that flag.
9. Release the lock without changing desired metadata, Terraform state,
   inventory, manifests, host trust, or the last-successful checkpoint. Default
   `show` creates no operation journal. Existing protected diagnostic logging
   may append only a sanitized invocation/result summary; it never records exact
   addresses, secrets, raw errors, or report payloads, and failure to write that
   optional diagnostic cannot trigger cluster mutation.

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

The implemented runner validates one canonical absolute executable and working
directory, passes only an explicit platform locale baseline plus allowlisted
entries, sets an owner-only child umask, closes stdin, invokes argument arrays
with `shell=False`, enforces a combined output bound while the child runs,
decodes strict UTF-8, and redacts protected values/paths before returning
captured output. Request/result representations omit argv, environment values,
working paths, and captured output. Terraform additionally fixes
`TF_DATA_DIR`, `TF_PLUGIN_CACHE_DIR`, `TF_IN_AUTOMATION`, `TF_INPUT`, `HOME`,
and checkpoint behavior under the canonical cluster root; ambient
`TF_CLI_ARGS*`, `TF_VAR_*`, workspace, proxy, and CLI-config values are never
forwarded.

Only Terraform version, init, recursive format check, JSON validate, saved plan
with detailed exit status, saved-plan JSON show, exact saved-plan apply, and
JSON output command objects exist. State/workdir commands require the matching
already-held application lock, retain Terraform backend locking, and use
absolute canonical backend/state/plan paths. Init additionally requires
caller-supplied unexpected-state candidate roots and checks them before launch.
The general Terraform service exposes no apply method; only the durable
execution owner may invoke that command. No destroy builder or apply/destroy
CLI execution path exists.

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
- `show` omits exact addresses by default and labels every included address as
  private, public, or route exposure only after explicit CLI disclosure; neither
  output mode may weaken secret, raw-error, environment, command, or sensitive-
  state redaction.
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
  help for all 12 operations, and exact per-operation flag/group allowlists,
  including rejection of every unrelated flag;
- `show` registry dispatch as read-only by default and read-only/sensitive-output
  only with `--include-addresses`, including section/node/live/fail-on parsing,
  mutual exclusions, deterministic filters, and rejection of every mutating
  flag;
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
- deterministic human and `deploy-scylla-vms.show/v1` JSON report projections,
  field-level desired/Terraform/live provenance, fresh/stale/unknown/unavailable/
  not-performed labels, omitted section/node behavior, and full redaction of
  secrets, raw environments/errors/commands, and sensitive Terraform inputs;
- `show` exact-address omission by default, private/public/route exposure labels,
  CLI-only disclosure, stdout-only address handling, and proof that addresses
  never enter logs/journals;
- read-only `show` canonical-root/ownership and shared-lock handling, local
  `terraform output -json` schema consumption without init/refresh/plan/state or
  inventory writes, provider/health/connectivity live-check timeouts and partial
  failures, and finding-to-exit-code behavior;
- deterministic provider-to-OS device correlation under changed enumeration
  order, absent/duplicate serials, root-on-partition/mapper/RAID ancestry,
  unexpected signatures, mounted/open holders, stale ownership markers, and
  retained-volume ownership;
- exact wipe confirmation/token validation, root-disk protection, and no
  wildcard/enumeration-order selectors in generated Ansible inputs;
- dry-run/check behavior proving storage resolution/discovery is read-only and
  that preparation, retirement, wipe, and post-initialization `auto` fallback
  are not selected;
- **Implemented offline subset (26.9.1):** operation-to-playbook mapping
  resolution now validates exact catalog coverage, the mandatory initial
  inventory preflight, read-only operation safety, selected conditional
  variants, mutually exclusive live/dead and in-place/reprovision branches,
  role/stable-ID limits, check/tag/diff/verbosity policy, allowlisted
  extra-variable schemas, inventory/readiness binding, and pre-health blockers.
  It returns a strict redacted plan and common journal checkpoint evidence
  without writing runtime files or invoking a process. Runtime operation
  execution, confirmation, journal persistence/resume, and verification remain
  unimplemented;
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
  playbook selected for read-only `check-jump-hosts`/`show`. It verifies that
  default `show` maps to no playbook and each explicit live-check combination
  maps only to the documented preflight/connectivity/health/evidence sequence.
- Parser-registry contract tests snapshot each subcommand's help/JSON schema and
  assert its exact common groups, operation flags, environment names, defaults,
  requiredness, and deprecation-free spelling. Documentation examples parse
  through the same registry. A generated documentation contract also verifies
  registry table columns/category membership, unique environment names,
  CLI-override existence/type/default compatibility, environment-only secret
  status, and the intentionally CLI-only denial set.
- Golden `show` reports cover healthy, stale, partial, unknown, conflicting, and
  redacted/address-disclosed fixtures; human and JSON views have deterministic
  host/section ordering and agree on findings and stable exit status.
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

In an approved ephemeral environment: deploy; default and explicit-live `show`;
no-op rerun; scale out; refresh monitoring; replace a failed node; scale in;
rolling OS upgrade; interruption and resume; drift refusal; and full destroy.
Prove both `show` modes leave state, inventory, cluster configuration, and cloud
resources byte/identity unchanged. Cover both a Block Volume path and,
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
- **Foundation status (26.9.1):** package metadata now declares Python 3.11 or
  newer; all 12 operation names, conservative safety classes, the OCI-only
  provider registry, stable exit-code constants, exact operation-specific
  parser/group allowlists, strict non-secret environment parsing/precedence,
  environment-only protected-input typing/redaction, immutable request models,
  and locally decidable required-together/mutual-exclusion/authorization rules
  are implemented. Strict TOML config loading, complete immutable
  `ClusterSpec` compilation/serialization/provenance, persisted-baseline change
  intent, and local desired/observed semantic reconciliation are also
  implemented. Provider/live reconciliation, threat/topology policy completion,
  and the non-Python compatibility matrices
  remain open, so Phase 0 is not complete.
- Acceptance: fixture-backed examples cover zero/multiple jump hosts, uneven
  zones, manager/monitor separation, explicit and provider-default
  datacenter/rack mappings, role-specific storage defaults, all three Scylla
  storage modes, and configuration precedence. Each of the 12 subcommands
  accepts only its documented groups/flags; the generated environment contract
  proves every supported non-secret and environment-only secret/internal
  variable is discoverable, uniquely typed, defaulted, and classified; and
  destructive acknowledgements have no env/config path.

### Phase 1 — safe CLI and state foundation

- Implement parser, models, provider registry, path validation, locking,
  redaction, process runner, journals, `show`, and other read-only commands.
- **Foundation status (26.9.1):** common and operation-specific parsing,
  non-secret precedence, strict cluster-name/request validation, canonical
  layout derivation, explicit owner-only initialization, existing
  symlink/hard-link/type/ownership/permission refusal, POSIX application
  locking, strict minimal cluster identity and operation journal schemas,
  generation/digest-guarded durable atomic JSON writes, unexpected local
  Terraform-state detection, environment-only protected-input boundaries,
  redaction, and typed CLI error mapping are implemented. CLI parsing and every
  registered operation remain non-mutating. The complete desired
  `ClusterSpec` now persists in identity-bound cluster schema v2 with a
  matching-held-lock write API; request differences are returned as typed
  change intent and read-only conflicts refuse. The local-only `show` subset now
  validates metadata/desired state and journals under a non-mutating exclusive
  read lock, renders independently versioned deterministic human/JSON reports,
  redacts protected references, and labels all absent external evidence
  truthfully. The controlled runner, anchored safe Terraform command/service
  boundary, stable `>=1.5.0,<2.0.0` toolchain probe, and strict independent
  Terraform output/host/storage v1 schemas are now implemented and fake-tested.
  Strict observed-manifest and generated-inventory records, deterministic local
  reconciliation, explicit-approval inventory refresh contracts, and local
  observed/inventory/trust `show` projections are also implemented. Candidate
  host-key collection, explicit trust persistence, route validation, and exact
  external inventory machine validation exist as internal fake-tested APIs.
  Provider refresh, live SSH/health validation, public trust orchestration, live
  `show` sources, shared read locking, and other functional read-only operations
  remain unimplemented, so Phase 1 is not complete.
- Acceptance: unit tests verify no secret flags, canonical external paths,
  traversal/symlink refusal, concurrency refusal, deterministic identity, stable
  errors, provenance-aware human/JSON `show` output, address redaction, and no
  state/inventory/provider/cluster writes.

### Phase 2 — OCI Terraform provisioning

- Implement reviewed modules for network/security/compute/storage and normalized
  outputs.
- **Partial source status (26.9.1):** the provider-neutral adapter protocol, offline
  OCI capability/input model, strict generated tfvars persistence, immutable
  source bundle/hash model, rollback-safe canonical staging, and staged-source
  command binding are implemented. Desired/config schema v2 adds explicit
  image-filter and managed-network CIDR contracts, and the offline adapter
  rejects no-match or newest-time ties using caller-supplied image/shape facts.
  Packaged `oci-root/v3` adds exact v2 Terraform variable types, provider-
  validated automatic OCI image lookup/selection checks and review output, OCI
  provider `~>9.1.0`, and a Terraform-generated lock selecting 9.1.0. Managed/
  existing network ownership, private/public jump routing, role NSGs, and strict
  intermediate network evidence are implemented and provider-schema validated.
  Stable-ID compute, Block Volume/local-NVMe storage branches, and complete
  strict outputs are implemented and the source is planning-ready. OCI discovery
  orchestration and credentialed sandbox plan validation remain unimplemented,
  so Phase 2 is not complete.
- Acceptance: `fmt`/`validate` pass; sandbox plan is least-privilege; per-cluster
  isolation and lock behavior are demonstrated; output fixtures preserve the
  resolved datacenter/rack and versioned storage schemas and validate; explicit
  block mode creates only declared volumes/attachments and records disposition.

### Phase 3 — inventory and baseline Ansible

- Implement deterministic transformation, SSH trust/routing, base role, ScyllaDB,
  storage discovery/preparation/retirement, separate Manager, and monitoring
  playbooks.
- **Local contract status (26.9.1):** deterministic provider-neutral inventory
  projection, strict persistence, source-manifest freshness, candidate diffing,
  explicit write approval, collision refusal, and unresolved-host-trust blocking
  are implemented as internal local APIs. The execution/toolchain foundation now
  adds stable ansible-core `>=2.17.0,<2.21.0` probes, controlled
  `ansible-inventory`/`ansible-playbook` builders and fake-tested service,
  owner-only ephemeral non-secret extra vars, state-anchored configuration, and
  the complete 33-entry registry/mappings and reviewed packaged source for all
  entries, including fail-closed validation-only maintenance contracts.
  Strict candidate-only OpenSSH discovery, explicit confirmation, immutable
  observation/inventory-bound trust persistence, deterministic known-host/SSH
  rendering, zero/one/multiple-jump validation, exact external inventory
  machine validation, readiness reports/gates, and redacted local `show`
  projection are also implemented and fake-tested. A separate internal
  candidate-only routed scanner now derives RFC 1918 private endpoints from
  stable-ID inventory selection, executes fixed `/usr/bin/ssh-keyscan` argv on
  one already trusted jump through strict generated SSH configuration, and
  returns only an address-free, provenance-bound in-memory collection. It does
  not persist or promote keys, and changed/existing trust remains blocked. The
  dependency-free
  `base-os` role is implemented for exact Ubuntu 24.04 on `amd64`/`x86_64` and
  `aarch64`. The package-only `scylla-install` source and immutable upstream
  role pin are packaged for ScyllaDB 2026.2 with authenticated vendored
  signing-key provenance. Wrapper-owned `scylla-configure` templates and strict
  seed/topology/configuration evidence are also packaged. Exact single-target
  `scylla-bootstrap` initial-seed/join-existing start and bounded membership
  evidence and strict cross-view cluster health are packaged. The shared
  lock-bound offline operation-plan resolver now integrates the public operation
  registry, conditional playbook catalog, command-policy validation,
  inventory/readiness gates, redacted digest projection, and PLAN-phase journal
  evidence without creating runtime files or invoking its runner. A separate
  matching-lock API now persists the strict independently versioned immutable
  operation request/plan binding beside an existing common PLAN journal and
  fail-closed revalidates unchanged pre-execution checkpoints. It distinguishes
  confirmation ambiguity, possible execution, destructive boundaries,
  interruption, failure, completion, and ambiguous history without advancing
  the journal or retrying work. A second immutable
  `ansible-operation-authorization/v1` companion now records only class-aware,
  operation-specific normalized confirmation proofs for an exact ready plan.
  It keeps ordinary approval, destructive class/scope, storage wipe, and
  monitoring restart separate, and resume validation v2 requires the exact
  unchanged companion for non-read-only operations while forbidding one for
  read-only work. A lock-bound internal checkpoint-preparation coordinator now
  loads the exact current canonical state and PLAN journal, derives the sole
  modeled `check-jump-hosts` intents, resolves the same deterministic plan, and
  sequences the existing immutable stores as binding then context then
  class-appropriate authorization. Exact existing records are reused without
  rewriting; matching binding-only and binding-plus-context prefixes can
  continue before execution, while mismatches, history drift, any execution
  companion, ambiguous duplicates, and unsafe state fail closed without
  deletion or rollback. Its independently versioned redacted report carries
  stage states, schemas/digests, blockers, and resumable-pre-execution truth.
  It performs no prompting, rendering, tool probing, execution, journal
  advancement, or CLI wiring; all other operations remain blocked as
  `operation-context-unmodeled` before writes. The lock-bound internal execution
  handoff now revalidates
  that exact checkpoint, persists one deterministic step as started before an
  injected fake-executor call, consumes authorization exactly once, validates
  per-playbook strict no-output receipts, and durably distinguishes success
  from failed, timeout, interruption, unreachable, malformed, and crash-left-
  started ambiguity. The independently versioned execution companion is
  owner-only, generation/digest guarded, append-only, and permanently blocks
  automatic retry after any uncertain outcome. The common v1 journal remains
  byte-for-byte at PLAN. A strict internal adapter now revalidates the exact
  current operation context and anchored command through the existing builder,
  invokes only the existing controlled Ansible service/runner, parses only the
  catalog-bound strict result contract, and returns the seven-field executor
  receipt without raw output. Fake-runner tests cover command/source/context
  drift, malformed output, timeout/interruption/unreachable mapping, redaction,
  single invocation, and execution-state-machine compatibility. The internal
  lock-bound one-step coordinator now requires the strict immutable
  `ansible-operation-context/v1` companion. The initial explicit value schema
  reconstructs bounded allowlisted read-only `check-jump-hosts` stable-ID,
  destination, depth, destination-check, and timeout combinations while
  re-deriving every address-bearing probe from current inventory. Context is
  written only after binding and before authorization/execution, and exact
  request/plan/binding/safe-intent digests prevent cyclic binding or guessed
  variables. The coordinator validates context and recomputes the request and
  exact plan before probing the Ansible pair, then recomputes machine readiness,
  constructs the controlled adapter, and calls the handoff once. Its redacted
  report adds only context schema/digest. Missing legacy, malformed, unsafe,
  drifted, complete, or recovery-required state fails closed; every non-modeled
  operation returns `operation-context-unmodeled` before tool probing or
  `started`. A separate internal `check-jump-hosts` orchestrator now reconstructs
  and verifies that exact read-only two-step plan before probing, calls the
  one-step coordinator once per next step, reloads and validates durable
  execution after every call, continues only an exact succeeded prefix, and
  bounds invocation count by the immutable plan. It returns the strict
  `ansible-check-jump-hosts-orchestration-report/v1` state
  `steps-succeeded`/`semantic-evidence-ready` after both exact receipt-bound
  semantic entries, `steps-succeeded`/`post-verification-pending` for legacy
  digest-only completion, or `execution-stopped`/`not-reached` after any
  uncertain outcome. The new owner-only, append-only
  `ansible-operation-evidence/v1` companion retains only exact inventory
  parity/count/provenance and stable-ID host/requested role-port pair outcomes;
  it rejects addresses, keys, routes, paths, raw output, commands, variables,
  environments, credentials, unknown targets, and reordered or conflicting
  entries. The adapter persists this projection after strict result parsing and
  before returning success, and the handoff verifies the exact persisted digest
  before a terminal succeeded write. Failure after remote read-only execution
  remains manual-recovery/no-retry. Complete re-entry is read-only and
  idempotent, and an in-memory helper now proves whether the exact dynamic
  public-v2 facts are available. A separate internal post-verifier/finalizer now
  reloads all canonical state, persists immutable
  `ansible-operation-finalization/v1`, appends exact `VERIFY/completed` evidence,
  and advances only this fully succeeded read-only operation to
  `SUCCEEDED/JOURNAL`. Companion-first and journal-generation guards make the
  exact finalization-only or VERIFY partial state idempotently recoverable;
  terminal re-entry writes nothing. Failed/unreachable/timed-out/interrupted/
  malformed/started execution remains manual-recovery and is not finalized.
  The finalizer exposes only the address-free public stable-ID and role/port
  result subset and does not alter the public no-write workflow. A narrow
  fake-runner-tested lifecycle coordinator now determines the exact durable
  stage and composes preparation, remaining-step orchestration, semantic
  verification, and finalization for only this modeled read-only operation. A
  separate internal fake-tested initiation owner now creates its exact
  generation-1 common PLAN prerequisite under the existing matching cluster
  lock, rejects active/replay/history conflicts, and leaves plan evidence for
  preparation's sole generation-2 same-phase append. The lifecycle reconstructs
  requests from immutable context when available, safely resumes binding/
  context, succeeded-execution, finalization-only, and VERIFY prefixes, and
  returns terminal success idempotently without writes or tool calls. Its
  strict lifecycle report carries only bounded
  stage/journal/execution/evidence/finalization
  states, counts, schemas, and digests; uncertain execution stops as manual
  recovery with no retry. A final internal one-call coordinator now accepts the
  exact bounded typed request and composes initiation with lifecycle under the
  same already-held operation lock. It initiates only missing/untouched
  generation-1 state, enters lifecycle directly for advanced exact prefixes,
  reports strict redacted
  `ansible-check-jump-hosts-operation-report/v1` state, and preserves terminal
  zero-write/zero-tool re-entry without duplicating any component state
  machine. Because every unimplemented mutating public workflow still produces
  a blocked plan and no CLI invokes the coordinator, handoff, adapter,
  orchestrator, finalizer, lifecycle coordinator, or one-call composition,
  this checkpoint has no public mutating execution path. Real-host validation
  of routed candidate collection, public trust orchestration, explicit
  canonical context schemas for other operations, generalized finalization/
  recovery review, reconciliation after execution, and public workflow
  integration remain incomplete, so Phase 3 is not complete.
- Acceptance: zero/one/multiple jump-host inventories validate; repeat Ansible
  run is idempotent; exact datacenter/rack hostvars reach Scylla configuration
  and are verified from Scylla; storage preparation excludes roots and unknown
  devices, survives device-order/reboot changes, and refuses signatures/backend
  drift; relabel drift is refused; no secret enters inventory or logs.

### Phase 4 — deploy and reconciliation

- Complete deploy, dry-run/plan/apply gates, postconditions, and resume.
- **Local saved-plan checkpoint status (26.9.1):** the earliest shared Phase 4
  pre-apply dependency is implemented as an internal, subprocess-free
  `deploy-scylla-vms.terraform-plan-checkpoint/v1` contract. Under the matching
  already-held operation lock, it accepts only an existing canonical saved plan
  plus bounded `terraform show -json` output and an exact supported toolchain,
  then writes immutable generation 1 at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-plan.json`. The
  checkpoint binds the operation request and initial PLAN journal, desired
  metadata, generated tfvars, staged source, canonical local-backend state
  serial and hashed lineage/snapshot, saved-plan bytes, plan JSON, and
  toolchain/format versions. It classifies no-change, create-only,
  non-destructive, and destructive plans; separately reports refresh drift as
  none, review-required, or conflict; and binds complete, destructive,
  replacement, deletion, and drift scopes through digests without retaining
  resource addresses or values. Its independently versioned
  `deploy-scylla-vms.terraform-plan-review/v1` projection contains only bounded
  counts/classes, generations, digests, and pre-apply state identity. Exact
  revalidation refuses any changed plan, state, desired input, source, toolchain,
  or journal; a later PLAN/CONFIRM journal is accepted only when its unique PLAN
  evidence names the exact checkpoint digest. Apply authorization remains
  `not-collected`, apply execution remains `unavailable`, and no apply/destroy
  builder, subprocess call, CLI path, provider call, or public deploy workflow
  was added.
- **Deploy PLAN journal-composition status (26.9.1):** the next narrow Phase 4
  dependency is complete as internal
  `compose_deploy_plan_journal`. It accepts only canonical state-root/cluster
  identity, one operation UUID, and the matching already-held deploy lock; it
  loads the checkpoint canonically rather than accepting plan content. It
  requires the exact initial `IN_PROGRESS/PLAN` journal preimage and revalidates
  checkpoint schema/generation/digest, deploy identity/classification/request,
  desired/tfvars/source/backend/state/toolchain bindings, saved-plan bytes, and
  current canonical state. It then performs only the existing-v1 legal
  generation-1 to generation-2 same-phase transition, appending one
  `PLAN/validated` event with the checkpoint digest and
  `terraform-plan-reviewed` summary. Exact generation-2 re-entry is zero-write;
  checkpoint-only state after a failed append is recoverable; all conflicting,
  duplicate, advanced, terminal, execution, stale, tampered, unsafe-path, or
  ambiguous states fail closed without overwrite, deletion, or rollback. The
  strict
  `deploy-scylla-vms.terraform-deploy-plan-composition-report/v1` projection
  carries created/reused state, journal/checkpoint/review schemas and digests,
  bounded counts/classes/booleans and address-free scope digests, plus
  authorization `not-collected`, execution intent `not-started`, apply
  execution `unavailable`, and destructive boundary `not-crossed`. Common
  journal v1 remains unchanged and stores no counts, addresses, plan values,
  paths, commands, environment, provider IDs, credentials, or secrets.
- **Controlled deploy PLAN orchestration status (26.9.1):** this Phase 4 slice
  is complete as internal `orchestrate_deploy_plan`. It accepts only canonical
  state-root/cluster identity, one deploy operation UUID, the matching
  already-held deploy lock, the controlled runner, and an explicit validated
  Terraform executable/toolchain dependency. Before any process call it loads
  the exact initial `IN_PROGRESS/PLAN` journal plus current metadata/desired,
  tfvars, staged source/work tree, canonical local backend/state identity, and
  unexpected-state/toolchain/lock bindings. It derives every runtime path and
  command internally through the existing anchored builder. Fresh execution
  runs only detailed `terraform plan` to the same-directory owner-only
  `<operation-uuid>.tfplan.staging`, accepts only exit 0/no-change or
  exit 2/change consistent with the later review, and runs exact
  `terraform show -json` against that staged plan. The strict in-memory parser
  now requires complete prior-state, configuration, planned-value, resource-
  change, drift, and output-change structures at supported format/toolchain
  versions. After revalidating every pre-run binding and unchanged plan bytes,
  the orchestrator atomically promotes the artifact to
  `<operation-uuid>.tfplan`, persists the immutable checkpoint, and invokes the
  existing journal composer in that order.
  Exact saved-plan-only recovery reruns show only after the current bound files
  prove they were not changed after planning; checkpoint-only recovery performs
  no Terraform call; exact generation-2 re-entry performs no write or process
  call. A staged partial, duplicate/temp artifact, conflicting plan/checkpoint,
  changed journal/state/source/tfvars/backend/toolchain, unsafe path/link/mode/
  size, failed or timed-out process, malformed/non-UTF-8/oversized show, or
  persistence ambiguity fails closed without deleting a reviewed plan or
  automatically replanning. The strict
  `deploy-scylla-vms.terraform-deploy-plan-orchestration-report/v1` projection
  contains only created/reused stage states, plan/checkpoint/review/journal
  schemas and digests, bounded classes/counts/booleans/scope digests, toolchain
  version, process counts, and retry/recovery flags. It contains no paths,
  commands, environment, plan bytes/JSON, addresses, provider IDs, values,
  diagnostics, credentials, or secrets. Authorization remains `not-collected`,
  execution remains `not-started`/`unavailable` at this planning layer, and no
  CLI or public deploy workflow invokes it.
- **Exact-plan apply-authorization status (26.9.1):** the next narrow Phase 4
  dependency is complete as internal `authorize_deploy_apply`. It accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, and an already-normalized typed proof. It derives
  the effective authorization class exclusively from the immutable reviewed
  plan and writes, only when apply is required,
  `deploy-scylla-vms.terraform-apply-authorization/v1` at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-authorization.json`.
  The owner-only immutable record binds exact cluster/operation/request,
  generation-2 PLAN journal, checkpoint/review/saved-plan, desired/tfvars/source,
  canonical local-backend/state, Terraform/plan-format, action/drift classes,
  bounded counts, and address-free change/destructive/replacement/deletion/drift
  scope digests. It stores only normalized proof enums/booleans and their digest;
  no prompt/entered text, operator/terminal/environment identity, resource
  address, plan value, command, path, key, credential, or secret is retained.
  No-change plans create no authorization and report apply `not-required`.
  Create/update-only plans require ordinary interactive approval or the
  permitted ordinary `--yes` fact. Replacement/deletion plans escalate to
  destructive and require ordinary approval, a separate normalized
  `--allow-destructive` fact, and exact matching destructive/replacement/deletion
  counts and scope digests. Benign refresh drift requires a separate interactive
  reviewed-plan acknowledgement because `--yes` cannot bypass drift; destructive
  refresh drift is a conflict and cannot be authorized. Absent initial state
  permits only a drift-free create-only plan. Narrow storage-wipe, recreation,
  reprovision, decommission, and other operation proofs are not supplied by this
  generic Terraform authorization.
  Exact re-entry reuses the byte-identical companion. Changed proof, plan,
  checkpoint, saved-plan bytes, journal, desired/tfvars/source/backend/state, or
  toolchain binding requires a new plan/operation and fails closed. The common
  v1 journal remains byte-for-byte at `IN_PROGRESS/PLAN`; authorization is a
  companion because no existing common-journal authorization evidence contract
  safely represents these semantics. Apply execution, intent consumption,
  destructive-boundary crossing, and state safeguard are owned by separate
  later internal layers. The
  current public `deploy` flag contract still rejects the `destructive` group,
  so no CLI can produce a destructive apply proof and no public workflow is
  enabled by this internal contract.
- **Immutable pre-apply state-safeguard status (26.9.1):** this narrow Phase 4
  dependency is complete as internal `safeguard_deploy_apply_state`. It accepts
  only canonical state-root/cluster identity, one operation UUID, and the
  matching already-held deploy lock; every checkpoint, review, authorization,
  journal, desired/tfvars/source/backend/state/toolchain fact is loaded from its
  canonical location. No-change plans report `not-required` and require
  authorization, safeguard, and backup companions to be absent. Apply-required
  plans require the exact immutable unconsumed authorization and unchanged
  generation-2 `IN_PROGRESS/PLAN` journal.
  Existing canonical local state must be a bounded singly linked owner-only
  regular `0600` file. Descriptor-relative no-follow reads bind its exact
  format/version, serial, hashed lineage, and full byte digest to the reviewed
  checkpoint and detect replacement or mutation before and after copying. The
  exact bytes are atomically published without overwrite at
  `<cluster-root>/terraform/backups/<operation-uuid>.terraform.tfstate`; only
  the minimal top-level state identity scalars are parsed, and no state
  resource, output, address, provider, or credential value is projected. A
  reviewed absent initial state instead requires drift-free create-only
  semantics, continued canonical-state absence, and clean unexpected-state
  checks; it creates no fake state or backup.
  The independently versioned owner-only immutable
  `deploy-scylla-vms.terraform-state-safeguard/v1` record at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-state-safeguard.json`
  binds the exact operation/journal, saved plan/checkpoint/review/authorization,
  desired/tfvars/source/backend/toolchain, present-state identity and backup
  digest/size or absent-state proof, and recovery policy. Ordering is validation
  then atomic backup when present, then immutable record. Backup failure leaves
  no record; record failure may leave an exact recoverable backup-only prefix.
  Exact backup/record re-entry is idempotent; missing, orphaned, unsafe,
  conflicting, or drifted artifacts fail closed without overwrite, deletion,
  rotation, pruning, automatic restore, or automatic retry. The strict
  `deploy-scylla-vms.terraform-state-safeguard-report/v1` projection retains
  only schemas/digests, bounded identity and size metadata, stage/recovery
  states, and explicit unconsumed/not-started/unavailable/not-crossed truth.
  The common journal remains byte-for-byte at PLAN, authorization remains
  unconsumed, and this slice constructs no apply/destroy command, invokes no
  subprocess/provider, and adds no CLI/public wiring.
- **Durable exact-plan apply-execution status (26.9.1):** this Phase 4 slice is
  complete as internal `execute_deploy_apply`. It accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and explicit validated Terraform
  executable/toolchain dependencies. It derives all paths, command arguments,
  environment, working directory, timeout, and output bound internally and
  accepts no plan/state/backup path, command, variable, environment, plan
  content, authorization, or timeout from its caller.
  Before intent it canonically revalidates the exact composed journal, saved
  plan/checkpoint/review, authorization, safeguard and exact backup or
  absent-state proof, metadata/desired, tfvars, source/work tree, local
  backend/current pre-apply state, unexpected-state policy, toolchain, command,
  classification, and destructive-proof bindings. No-change/not-required,
  absent/consumed authorization, conflicting drift, missing safeguard, replay,
  ambiguous artifact, or any stale/tampered/unsafe binding fails before a
  process call.
  The sole new builder command is exact saved-plan
  `terraform apply -input=false -no-color -lock=true -lock-timeout=30s
  <canonical-operation-plan>`, under the canonical cluster working directory
  with controlled `TF_DATA_DIR`, plugin cache, local backend, and no
  auto-approve/destroy/target/replace/refresh-only/parallelism/variable/
  workspace/proxy/config or ambient CLI argument.
  The owner-only
  `deploy-scylla-vms.terraform-apply-execution/v1` transition record lives at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-execution.json`.
  It binds the exact journal, plan/checkpoint/review/composition,
  authorization/proof, safeguard/backup-or-absence, desired/tfvars/source/
  backend/pre-apply state/toolchain, command, and plan classification through
  schemas, generations, and digests without retaining raw paths, command,
  environment, plan/state/output, addresses, provider IDs, diagnostics,
  credentials, or secrets.
  Ordering is complete validation, durable retry-safe `prepared`, one v1-legal
  journal transition to `IN_PROGRESS/EXECUTE` with
  `terraform-apply-intent` evidence, durable `started` generation 2 that
  consumes the immutable authorization binding, exactly one controlled runner
  call, then bounded generation-3 process outcome. A prepared prefix may resume
  only after exact revalidation; once started is durable, re-entry makes zero
  process calls. Timeout, interruption, nonzero exit, invalid/oversized output,
  malformed result, runner error, crash, or terminal-write ambiguity is
  uncertain, manual-recovery-required, verification-required, and never
  automatically retried, restored, rolled back, deleted, replanned, or
  reapplied. Exit zero records only
  `process-succeeded-verification-pending`; the common journal remains
  nonterminal at EXECUTE and no stdout is interpreted as success.
  The independently versioned strict redacted report returns only bounded
  state/exit status, current-call and may-have-occurred invocation truth,
  authorization-consumption and recovery/verification flags, journal state,
  and schemas/digests. The layer captures no Terraform output, performs no
  state/observation/inventory reconciliation or finalization, runs no destroy,
  and has no CLI/public deploy wiring.
- **Strict post-apply verification/reconciliation status (26.9.1):** this Phase
  4 slice is complete as internal `verify_deploy_apply`. It accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, the controlled runner, and explicit validated
  Terraform executable/toolchain dependencies. It canonically reloads the
  exact successful execution plus journal, saved plan/checkpoint/review/
  composition, consumed authorization, safeguard/backup-or-absence,
  metadata/desired, tfvars, source/work tree, backend, toolchain, and local
  state bindings. Every not-started, no-change, failed, uncertain,
  manual-recovery, stale, unsafe, or ambiguous state is refused before a
  process call.
  Post-apply state is read as a bounded owner-only no-follow regular file and
  must have supported state format/toolchain identity. Existing state must
  preserve the reviewed lineage while advancing serial and byte digest;
  verified absent initial state permits only a new valid lineage and positive
  serial for a drift-free create-only plan. Descriptor/path identity checks
  surround the external read and persistence boundaries, and unexpected
  alternate state/backend metadata remains forbidden.
  Ordering is exact process/state validation, one legal nonterminal journal
  transition to `IN_PROGRESS/VERIFY` with a digest-bound prior-observation or
  absence baseline, the existing fully anchored
  `terraform output -json -no-color -state=<canonical-state>` command, strict
  complete output parsing, exact host/image/network/topology/storage/source/
  desired reconciliation, guarded `deploy-scylla-vms.observed/v1`
  persistence, then immutable owner-only
  `deploy-scylla-vms.terraform-apply-verification/v1` at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-verification.json`.
  The companion binds pre/post state identity, execution, journal,
  checkpoint/review/composition, authorization, safeguard, metadata/desired,
  tfvars/source/backend/toolchain, output/observation schemas and digests,
  generations, reconciliation status, and bounded role counts without state
  or output contents, addresses, provider IDs, commands, environment, paths,
  diagnostics, credentials, or secrets.
  An exact observation-only partial prefix after companion-write failure is
  recoverable without another output call when its timestamp, identity, and
  current exact desired reconciliation prove it belongs to the VERIFY prefix.
  Exact completed re-entry is zero-write/zero-process. Every other ambiguity
  after apply requires manual review and never reruns apply. Success means only
  Terraform infrastructure observation is reconciled and ready for later
  inventory/trust work; the common journal remains `IN_PROGRESS/VERIFY`.
- **Verified-apply inventory-generation status (26.9.1):** the next narrow Phase
  4 slice is complete as internal `generate_deploy_inventory`. It accepts only
  canonical state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It loads canonical paths internally and requires
  the exact successful
  `deploy-scylla-vms.terraform-apply-verification/v1`, its process-success
  execution and saved-plan checkpoint bindings, unchanged
  `IN_PROGRESS/VERIFY` journal, and current metadata/desired/tfvars/source/
  observation identity, generations, and digests before any write. Caller
  inventory content, paths, observations, hosts, groups, routes, addresses,
  variables, and generations are not accepted.
  The owner uses only the existing strict observed-manifest reconciliation and
  deterministic observation-to-inventory transformation. It preserves stable
  logical identity, exact host-manifest membership/provider/topology/storage,
  collision-checked role/zone/datacenter/rack groups, jump-only public endpoint
  policy, RFC 1918 private routing, structured direct/ProxyJump metadata,
  approved SSH user/port policy, and mandatory host-key checking. It writes or
  reuses only owner-only `deploy-scylla-vms.inventory/v1` at
  `<cluster-root>/ansible/inventory.yml`; no inventory content or endpoint is
  copied into public output.
  The independently versioned immutable
  `deploy-scylla-vms.terraform-apply-inventory/v1` companion belongs at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-inventory.json`.
  It binds operation/journal/verifier/execution/checkpoint, desired metadata,
  tfvars/source/observation, and exact inventory schema/generation/digests plus
  bounded role/zone/host counts and address-free group/topology/route digests.
  The strict report adds only created/updated/reused state, those bounded
  schemas/counts/digests, trust classification, next-step requirement,
  nonterminal journal state, and recovery truth.
  Exact current inventory is reused byte-for-byte. A newer verified observation
  with the same deterministic model may advance the guarded inventory
  generation. Existing inventory identity, membership, provider, topology,
  endpoint, or route conflicts fail closed. Existing trust is loaded but never
  rewritten: exact current provenance reports `current`; absent trust reports
  `missing`; semantically matching older generation/digest provenance reports
  `stale` and requires revalidation; membership/provider/endpoint/route or
  forward-generation conflicts fail before inventory writes. Ordering is
  validate, generate in memory, persist/reuse inventory, then persist the
  companion. An exact inventory-only prefix after companion-write failure may
  recover without rewriting inventory; conflicting orphan state fails closed.
  This layer renders no `known_hosts`, `ssh_config`, or `ansible.cfg`, performs
  no Terraform, SSH, or Ansible process call, collects no machine evidence,
  and leaves the common journal exactly `IN_PROGRESS/VERIFY`.
  This inventory owner deliberately leaves SSH trust establishment to the
  separate operation-bound owner below. Machine inventory validation/readiness,
  Ansible deploy context/execution, deploy finalization, resume across later
  stages, and public deploy wiring remain incomplete, so Phase 4 is not
  complete.
- **Verified-inventory SSH-trust status (26.9.1):** the next narrow Phase 4
  slice is complete as internal `establish_deploy_ssh_trust`. It accepts only
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, existing typed direct candidates and routed
  candidate collections, and normalized
  `deploy-scylla-vms.terraform-apply-trust-proof/v1` per-key proofs. The only
  proof modes are explicit operator confirmation without supplied text and an
  independently supplied exact SHA-256 fingerprint. It accepts no endpoints,
  routes, ports, paths, generic `--yes`, commands, environment, host-key
  bypass, or free-form prompt content.
  Before every write it canonically revalidates the exact
  `IN_PROGRESS/VERIFY` journal, successful apply verifier, immutable
  `deploy-scylla-vms.terraform-apply-inventory/v1` companion, current metadata/
  desired/tfvars/source/observation/inventory bindings, and any existing trust
  and deterministic derivatives. Every endpoint, port, stable/provider
  identity, and jump route comes from the current inventory. Candidate
  identity, endpoint, source observation, approved Ed25519 or NIST P-256 ECDSA
  key material/fingerprint, and routed collection/jump provenance must match
  exactly. Malformed, oversized, duplicate, conflicting, unsupported, missing,
  extra, stale, wrong-route, wrong-generation, and wrong-source inputs fail
  closed.
  Initial direct jump trust is one guarded stage:
  `jump-trust-current` with `private-trust-pending`. Routed private candidates
  may advance trust only on a later exact call when the jump trust was current
  at collection and remains current. An untrusted jump and its routed private
  candidates cannot form one simultaneous chain. Existing exact complete trust
  is reusable; semantically matching stale complete trust advances to the new
  observation/inventory generation only with exact per-key revalidation proofs
  and no candidates. Changed keys, identities, membership, endpoints, or routes
  remain conflicts requiring the separate replacement workflow.
  Persistence uses only guarded owner-only `deploy-scylla-vms.ssh-trust/v1`
  `ansible/trust.json` plus deterministic `known_hosts` and `ssh_config`.
  Ordering is canonical validation, trust/derivative persistence or exact
  derivative recovery, then—only for a complete current host set—immutable
  owner-only `deploy-scylla-vms.terraform-apply-trust/v1` at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-trust.json`.
  The companion binds operation/request/journal/verifier/inventory companion,
  metadata/desired/source/observation/inventory/trust schemas, generations, and
  digests, normalized confirmation-proof digest, bounded jump/private/total
  counts, address-free route digest, and derivative byte digests. It contains
  no address, provider ID, key, fingerprint, route, file content, protected
  path, credential, or secret.
  An exact trust-only prefix after derivative or companion failure recovers
  without scanning; companion-without-trust and mismatched companion,
  trust, or derivatives fail closed. Reports expose only
  `jump-trust-current`/`complete`, `private-trust-pending`/
  `machine-inventory-validation-required`, bounded states/counts/schemas/
  digests, source/proof/derivative status, and recovery truth. The common
  journal remains exactly `IN_PROGRESS/VERIFY`. This layer collects no
  candidates, invokes no Terraform, SSH, keyscan, `ansible-inventory`, or
  playbook process, performs no TOFU/`accept-new`/`ProxyCommand` bypass, and
  does not validate machine inventory/readiness, execute Ansible, finalize
  deploy, or add public/CLI wiring. Those later stages remain incomplete, so
  Phase 4 is not complete.
- **Operation-bound machine-readiness status (26.9.1):** the next narrow Phase
  4 slice is complete as internal `validate_deploy_ansible_readiness`. It
  accepts only canonical state-root/cluster identity, one operation UUID, the
  matching already-held deploy lock, a controlled runner, and an exact
  validated sibling `ansible-playbook`/`ansible-inventory` pair plus explicit
  supported toolchain dependency. It accepts no caller paths, commands,
  arguments, environment, normalized inventory, readiness result, hosts,
  groups, routes, or variables.
  Before a process call it canonically revalidates the unchanged
  `IN_PROGRESS/VERIFY` journal, successful apply verifier, immutable apply
  inventory and complete apply-trust companions, and current metadata/desired/
  Terraform source/observation/inventory/trust plus deterministic
  `known_hosts` and `ssh_config`. Missing or staged trust, stale provenance,
  derivative changes, companion conflicts, and unsafe or ambiguous paths fail
  before the runner.
  The owner renders or exact-reuses only canonical owner-only
  `<cluster-root>/ansible/ansible.cfg` through the packaged deterministic
  renderer. Controller home, local temporary data, fact cache, control data,
  and log remain below the cluster root; the config binds exact canonical
  inventory and SSH config, the latter binds exact `known_hosts`, and strict
  host-key checking remains enabled. Ambient path, proxy, callback/plugin,
  config, workspace, and variable discovery remain unavailable.
  It probes both exact executables through the controlled runner, requires the
  same stable ansible-core `>=2.17.0,<2.21.0` identity and the supplied
  dependency, then runs only controller-local
  `ansible-inventory --inventory <canonical-inventory> --list`. Strict
  normalized parsing proves exact persisted host/group/hostvar, role/zone/
  datacenter/rack, SSH identity/port, endpoint, ProxyJump, and trust-derivative
  parity with no extra, missing, duplicate, unsafe, or colliding data. Raw
  machine JSON and protected runtime identities remain in memory only and are
  never persisted or projected.
  The existing readiness model must report fresh source and machine evidence,
  complete current trust, and valid deterministic routes before persistence.
  The independently versioned immutable owner-only
  `deploy-scylla-vms.terraform-apply-readiness/v1` belongs only at
  `<cluster-root>/terraform/plans/<operation-uuid>.terraform-apply-readiness.json`.
  It binds operation/journal/verifier/inventory/trust companions, current
  metadata/desired/source/observation/inventory/trust, Ansible source/config,
  executable/toolchain and machine-evidence digests, readiness schema/digest/
  status, bounded counts, and address-free group/topology/route digests. It
  explicitly records remote connectivity, host health, and playbook execution
  as `not-performed`, with no addresses, provider IDs, hostvars, keys,
  fingerprints, raw JSON, config text, command, environment, protected path,
  credential, or secret.
  Ordering is canonical validation, config render/reuse, two version probes,
  one local inventory call, strict parsing/readiness, exact context reload,
  then companion persistence. Exact current companion re-entry is zero-process;
  companion-write failure leaves no false readiness and may safely repeat the
  local read-only checks. Conflicting immutable evidence fails closed. The
  common journal remains exactly `IN_PROGRESS/VERIFY`; this layer runs no
  playbook, inventory preflight, connectivity/evidence collection, SSH/keyscan,
  Terraform, or remote host call and performs no Ansible deployment or deploy
  finalization. Remote connectivity, Ansible deployment, deploy finalization,
  resume across those later stages, and all public/CLI deploy wiring remain
  incomplete, so Phase 4 is not complete.
- **Deploy-specific Ansible PLAN/context-binding status (26.9.1):** the next
  narrow Phase 4 slice is complete as internal `bind_deploy_ansible_plan`.
  The generic Ansible operation binding is intentionally not reused because
  its contract requires a PLAN-phase journal checkpoint, while a verified
  Terraform deploy is already at `IN_PROGRESS/VERIFY`. The deploy-only API
  accepts canonical state-root/cluster identity, one operation UUID, and the
  matching already-held deploy lock; it accepts no caller plan, steps,
  playbooks, limits, variables, paths, commands, environment, readiness model,
  or runtime evidence.
  Before persistence it canonically revalidates the exact successful apply
  verification, generated-inventory, complete-trust, and local machine-
  readiness chain plus current metadata/desired/Terraform source/observation/
  inventory/trust, trust derivatives, rendered Ansible config, packaged
  Ansible source, and complete catalog digest. Missing, stale, drifted,
  mismatched, unsafe, ambiguous, or semantically uncertain evidence fails
  closed.
  The strict allowlisted
  `deploy-scylla-vms.ansible-deploy-context/v1` record belongs only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-context.json`.
  Its nested intent schema records only explicit safe `unmodeled`,
  `not-collected`, and `not-performed` states for connection/host evidence,
  storage wipe consent, bootstrap/empty-cluster proof, package/task/backend,
  and monitoring-startup decisions not derivable from current canonical state.
  It stores no arbitrary variable map, address, provider ID, hostvar, route,
  key/fingerprint, device path, command, environment, credential, secret,
  token, password, prompt, or raw evidence.
  The independently versioned
  `deploy-scylla-vms.ansible-deploy-plan/v1` record belongs only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-plan.json`.
  It deterministically expands the exact 21 registry-positioned deploy
  mappings, including both connectivity checks, jump/non-jump `base-os`
  conditions, every role target, and the optional explicit Manager-task
  condition. Single-logical-host policies expand by sorted stable ID; all
  other targets remain sorted stable-ID sets. Each step binds condition state,
  role, classification, limit/serial/check-mode policy, target and allowlisted-
  variable digests, exact playbook source hash, command-intent digest, status,
  and stable blocker enums. Identity is never derived from address or list
  position.
  This slice deliberately emits a deterministic blocked plan: remote
  connectivity, host evidence, base OS, storage discovery/preflight/prepare/
  postcheck, wipe consent, bootstrap/empty-cluster proof, cluster health,
  quorum/backup/capacity, Manager/backend/task authorization, monitoring
  startup/targets, package/configuration intent, and public deploy orchestration
  remain `not-performed`, `not-collected`, or `unmodeled` as applicable.
  Local readiness alone never makes a step executable.
  Persistence order is validate, build both records in memory, persist/reuse
  context, then persist/reuse plan. Exact records are reusable; an exact
  context-only prefix may recover. Plan-without-context, changed records,
  generic operation companions, advanced/conflicting state, and unsafe paths
  fail without overwrite, deletion, rollback, or journal transition. The
  strict report contains only schemas/digests, bounded playbook/role/step/
  target and status counts, blocker enums/digest, and catalog/source/readiness
  bindings. The common journal remains `IN_PROGRESS/VERIFY`; no inventory-
  preflight, connectivity, evidence, SSH, Terraform, or Ansible process runs,
  and no deploy authorization, execution, finalization, CLI, or public workflow
  is added. Those later Phase 4 slices remain incomplete.
- **Deploy read-only prerequisite execution/evidence status (26.9.1):** the next
  narrow Phase 4 slice is complete as internal
  `execute_deploy_ansible_prerequisites`. It accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and exact explicit Ansible executable/
  toolchain dependencies. It accepts no caller plan, step, playbook, limit,
  variable, path, command, environment, evidence, or result. Before effects it
  revalidates the full verified Terraform/apply/inventory/trust/readiness chain,
  rendered controller files and trust derivatives, packaged source/catalog,
  unchanged `IN_PROGRESS/VERIFY` journal, and byte-exact immutable deploy
  context and all 21 mapped plan positions.
  Only plan mappings one and two are executable here. The controller-local
  `inventory-preflight` receives the exact complete sorted stable-ID set and
  service-injected current inventory/machine-evidence bindings without a host
  connection. The initial `connectivity-check` uses that same complete host set,
  fixed bounded SSH timeouts, strict current trust/routes, and an empty
  destination-probe list. The anchored service supplies canonical config,
  inventory, SSH trust, cwd, locale/environment, timeout/output limits, and
  strict UTF-8/redaction; arbitrary tags, skip-tags, limits, extra variables,
  callback/plugin/config/inventory overrides, and destination probes remain
  impossible.
  The generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-prerequisite-execution/v1` companion belongs
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-prerequisite-execution.json`.
  Each step is durably `started` before its runner call. Strict parsed semantic
  evidence is then persisted before terminal step state in the independently
  versioned immutable-prefix
  `deploy-scylla-vms.ansible-deploy-prerequisite-evidence/v1` companion at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-prerequisite-evidence.json`.
  It binds operation/journal/context/plan/readiness/catalog/source/toolchain,
  both step command/result/evidence digests, host count/set and route/trust
  digests, and bounded statuses/counts without addresses, provider IDs, routes,
  keys/fingerprints, raw output/events, commands, variables, environment,
  protected paths, credentials, or secrets.
  Exit zero alone never proves success: inventory parity and complete unique
  host results must match exactly, and any failed/unreachable connectivity is a
  failure. A started crash, timeout, interruption, malformed/non-UTF-8/
  oversized result, failed semantic evidence, or post-invocation persistence
  failure requires manual recovery and permanently forbids automatic retry.
  An exact succeeded preflight prefix may continue to connectivity; exact full
  completion re-entry makes zero process calls. Full success reports only
  `deploy-prerequisites-ready` for inventory parity and initial SSH
  connectivity. The immutable blocked deploy plan is not rewritten; a later
  reconciliation/rebind slice must consume this evidence. Host evidence and all
  OS/storage/package/configuration/bootstrap/health/Manager/monitoring,
  authorization, mutating execution, finalization, resume across later stages,
  CLI, and public deploy wiring remain pending. The common journal remains
  exactly `IN_PROGRESS/VERIFY`, so Phase 4 is not complete.
- **Deploy prerequisite-evidence reconciliation status (26.9.1):** the next
  narrow Phase 4 slice is complete as internal
  `reconcile_deploy_ansible_plan`. It accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. It accepts no caller plan, status, evidence, step, playbook,
  target, limit, variable, command, environment, path, runner, executable, or
  toolchain dependency. It canonically reloads the unchanged
  `IN_PROGRESS/VERIFY` journal, full verified Terraform/apply/inventory/trust/
  readiness chain, immutable deploy context/original plan, completed
  prerequisite execution/evidence, packaged source, and catalog before
  persistence.
  The owner recomputes and requires the exact original 21-position deploy
  mapping plus every expanded sequence, condition, classification, target,
  limit, serial, check-mode, variable, source, and command digest. Missing,
  incomplete, failed, uncertain, reordered, extra, stale, mismatched, or
  drifted prerequisites and every journal/context/plan/readiness/source/catalog/
  mapping conflict fail closed and require a new operation with explicit
  re-plan; the owner never silently adapts an existing operation.
  The independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-effective-plan/v1` companion belongs only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-effective-plan.json`.
  It binds the exact operation/journal/context/original plan/readiness/
  prerequisite execution/evidence/source/catalog artifacts and a deterministic
  effective-plan digest. Only the exact inventory-preflight and initial
  complete-host connectivity steps become `succeeded` and semantic-evidence
  bound. Inactive conditions remain `not-performed`. Under the unchanged
  ordered mapping the next active positions are mutating, so no later read-only
  step is currently eligible; final-route connectivity, health, and host
  evidence remain truthfully `not-performed` rather than being promoted out of
  order. Every mutating, sensitive, and destructive step remains `blocked`
  with its original bounded blockers plus class-specific unavailable-execution
  and uncollected-authorization blockers. Storage/wipe, bootstrap/empty-cluster,
  health/quorum/backup/capacity, Manager/backend/tasks, monitoring, package/
  configuration, and public-orchestration blockers remain explicit.
  Validation/building completes in memory before atomic no-follow persistence.
  Exact reuse is zero-write; write failure leaves the original context, plan,
  execution, evidence, and journal unchanged. The strict report contains only
  schemas/digests, total/succeeded/eligible/blocked/not-performed counts, safe
  next-eligible playbook names and stable-ID counts, blocker enums/digest, and
  journal status/phase. This slice creates no authorization or execution
  intent, invokes no process, advances no journal phase, performs no
  finalization, and adds no CLI/public deploy wiring. The next read-only host-
  evidence execution/reconciliation stage and all mutations remain pending, so
  Phase 4 is not complete.
- **Deploy pre-mutation host-evidence checkpoint status (26.9.1):** the next
  narrow Phase 4 slice is complete as internal
  `execute_deploy_pre_mutation_host_evidence`. It accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and exact validated Ansible executable/
  toolchain dependencies. Caller-supplied playbook, target, limit, variable,
  path, command, environment, evidence, and result input is absent.
  Before any invocation it canonically reloads and revalidates the unchanged
  `IN_PROGRESS/VERIFY` journal, full verified Terraform/apply/inventory/trust/
  readiness chain, rendered controller/trust files, immutable deploy context/
  original/effective plans, successful prerequisite execution/evidence,
  packaged source, catalog, and toolchain/executable identities. It requires
  the effective plan to retain only the first inventory-preflight and initial
  connectivity mappings as succeeded; every later mapped read-only step,
  including final `evidence-collect`, must remain `not-performed`, and every
  active mutating/sensitive/destructive step must remain blocked.
  This owner defines a distinct digest-bound checkpoint kind,
  `pre-mutation-host-evidence`. It partitions the exact complete sorted
  stable-ID inventory into deterministic jump-host, Scylla, Manager, and
  monitoring role batches and invokes only the existing read-only
  `evidence-collect` source through the anchored Ansible service. The service
  owns canonical config/inventory/trust/cwd/environment, fixed bounded
  timeout/output, strict UTF-8/redaction, and the sole allowlisted evidence
  timeout variable; arbitrary tags, callback/plugin/config/inventory
  overrides, destination probes, or caller limits/variables remain impossible.
  The generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-pre-mutation-host-evidence-execution/v1`
  companion belongs only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-pre-mutation-host-evidence-execution.json`.
  Each batch is durably `started` before its runner call. Strict semantic
  evidence is persisted before terminal success in the independently
  versioned immutable-prefix
  `deploy-scylla-vms.ansible-deploy-pre-mutation-host-evidence/v1` companion at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-pre-mutation-host-evidence.json`.
  Exit zero alone is insufficient: parsing requires the exact host-evidence
  schema, one unique result for every selected stable ID, exact batch role,
  exact allowlisted service applicability, bounded counts/enums, and no
  protected facts.
  Persisted semantic facts are limited to stable ID, role, evidence status,
  OS family/version/architecture, truthful reboot-required collection status,
  bounded CPU/memory and mount/block-device availability/counts, hashed mount/
  device-set evidence, allowlisted service states, role-health status/digest,
  and bounded blocker enums. Reports retain only schemas/digests and bounded
  role/OS/architecture/completeness/blocker counts. Addresses, provider IDs,
  raw device paths/serials, keys/fingerprints, routes, raw module output/logs,
  commands, variables, environment, paths, credentials, and secrets are never
  retained.
  Unsupported OS/version/architecture remains successfully parsed evidence
  with explicit bounded blockers. Missing/extra/duplicate/wrong-role or
  protected evidence, nonzero/failed/unreachable results, crash, timeout,
  interruption, malformed/non-UTF-8/oversized output, or post-invocation
  persistence failure requires manual recovery and permanently forbids
  automatic retry. An exact succeeded role prefix may continue; exact complete
  re-entry makes zero runner calls. Validation precedes durable intent,
  controlled invocation, strict parsing, semantic evidence, then terminal
  success. The owner never rewrites/reconciles the effective plan, marks the
  mapped final evidence step succeeded, authorizes base OS/storage/package
  work, runs storage discovery, writes diagnostics evidence, persists raw
  evidence, changes the common journal, finalizes deploy, or adds CLI/public
  wiring. A later reconciliation slice must consume this distinct checkpoint
  before any mutation; Phase 4 remains incomplete.
- **Deploy pre-mutation host-evidence reconciliation status (26.9.1):** the
  next narrow Phase 4 slice is complete as internal
  `reconcile_deploy_pre_mutation_host_evidence`. It accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. Caller statuses, plans, evidence, steps, variables, commands,
  paths, runners, executables, and toolchains are absent. It canonically reloads
  and revalidates the unchanged `IN_PROGRESS/VERIFY` journal, complete verified
  Terraform/apply/inventory/trust/readiness chain, immutable deploy context and
  original plan, prerequisite execution/evidence, prior effective plan,
  complete pre-mutation execution/evidence, packaged source, and catalog.
  The owner recomputes the exact 21-position mapping and every expanded
  sequence, condition, class, target, limit, serial, check-mode, variable,
  source, and command identity. It requires exact successful role batches with
  complete unique stable-ID coverage and matching provenance; missing, extra,
  duplicate, reordered, wrong-role, failed, uncertain, stale, conflicting, or
  drifted records fail before persistence and require explicit re-plan/new
  operation where applicable.
  The independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-host-evidence-reconciliation/v1` companion
  belongs only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-host-evidence-reconciliation.json`.
  It binds the prior effective plan and exact pre-mutation checkpoint/execution/
  evidence artifacts, retains the original mapping identities and digests, and
  records only aggregate address-free host-gate counts/digests plus the new
  effective step statuses. The gate evaluator uses only facts that the bounded
  checkpoint can prove: exact Ubuntu 24.04 and supported guest architecture,
  reboot requirement, allowlisted service states, CPU/memory presence, root
  mount evidence, and role-applicable Scylla device evidence. Missing facts
  remain unknown/blocking. It does not infer package readiness, storage
  ownership or wipe safety, cluster emptiness, Scylla health, replication,
  quorum, backup policy, or post-removal capacity.
  Original inventory preflight and initial connectivity remain evidence-bound
  `succeeded`. The distinct checkpoint is evidence-bound only through
  reconciliation metadata and never completes the original final mapped
  `evidence-collect`, which remains `not-performed`. Only next-ordered
  role-scoped `base-os` steps whose applicable host gates all pass may be
  labeled `evidence-ready-authorization-required`; that state retains explicit
  uncollected-authorization, unavailable-mutation-execution, and unavailable-
  public-workflow blockers and is never executable or eligible. Unsupported
  platform, required/unknown reboot, active/unknown service, and unavailable
  capacity/mount/device facts remain bounded blocker enums. Storage discovery/
  preflight/prepare/wipe, packages, configuration, bootstrap, health/quorum/
  backup/capacity, Manager, monitoring, final evidence, and later ordered
  read-only gates remain blocked or not performed.
  Validation and record construction finish in memory before atomic no-follow
  owner-only persistence. Exact reuse is zero-write; conflicts never overwrite,
  delete, roll back, or adapt an operation. The strict report contains only
  schemas/digests, step status counts, host-gate counts/digests, grouped next
  authorization-required playbook/role/stable-ID counts, blocker enums/digest,
  and journal status/phase. This owner creates no authorization record,
  mutating intent, runner/toolchain call, journal transition, finalization, or
  CLI/public deploy path. Mutation authorization/execution, later evidence
  gates, finalization, and public deploy remain pending, so Phase 4 is not
  complete.
- **Deploy base-OS authorization status (26.9.1):** the next narrow Phase 4
  slice is complete as internal `authorize_deploy_base_os`. Its only caller
  inputs are canonical state-root/cluster identity, one operation UUID, the
  matching already-held deploy lock, and an already-normalized typed ordinary
  approval proof. It accepts no caller step, playbook, target, limit, variable,
  command, path, classification, scope, prompt text, or operator identity.
  Before persistence it canonically reloads and revalidates the unchanged
  `IN_PROGRESS/VERIFY` journal and complete verified Terraform/apply/inventory/
  trust/readiness, deploy context/original/effective plan, prerequisite,
  pre-mutation host-evidence, host-reconciliation, source, and catalog chain.
  The complete authorizable set is derived exclusively from exact
  `evidence-ready-authorization-required` statuses. Every such step must be an
  active mutating `base-os` instance at mapping position three; no blocked,
  non-ready, later storage/package/configuration/bootstrap/Manager/monitoring/
  final-evidence step or broader/narrower target set can be authorized.
  `base-os` requires ordinary interactive approval or the PLAN-permitted
  `--yes` automation proof. Destructive flags/scope proof are rejected as
  inapplicable and no wipe, replacement, decommission, bootstrap, or other
  narrow destructive consent is collected. The independently versioned
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-base-os-authorization/v1` record belongs
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-base-os-authorization.json`.
  It binds operation/cluster/journal, deploy context and plans, prerequisite and
  pre-mutation execution/evidence, host reconciliation, readiness, catalog,
  source, exact step sequence/playbook/source/command/target/variable/evidence
  digests, stable-ID set digest/count, mutating classification, and normalized
  proof method/booleans/digest. It stores no prompt or free-form operator text,
  user identity, address, provider ID, route, key, raw command/variable/
  environment, protected path, credential, or secret.
  Exact unchanged re-entry is zero-write reuse. Changed proof, scope, plan,
  evidence, readiness, source/catalog, journal, or any other bound state fails
  closed and requires re-plan/new operation; there is no invented expiry.
  Authorization remains unconsumed in this immutable artifact; the subsequent
  exact-scope execution owner represents consumption in its durable started
  record immediately before effect. The authorization report contains only
  schemas/digests, authorization state/method, mutating class, exact playbook
  instance and stable-ID counts/set digest, unchanged non-authorized step
  status counts/digest, `consumed=false`, execution unavailable, and journal
  status/phase. This authorization slice creates no execution record or intent,
  runner/toolchain call, step-status change, journal transition, finalization,
  CLI, or public deploy wiring. Execution is owned only by the next separately
  versioned internal slice; every later deploy stage remains pending, so Phase 4
  is not complete.
- **Deploy base-OS exact-scope execution status (26.9.1):** the next narrow
  Phase 4 slice is complete as internal `execute_deploy_base_os`. Its only
  caller inputs are canonical state-root/cluster identity, one operation UUID,
  the matching already-held deploy lock, a controlled runner, and exact
  validated sibling Ansible executable/toolchain dependencies. It accepts no
  caller step, playbook, target, limit, variable, path, command, environment,
  authorization, result, or loop bound. Before any mutating playbook call it
  canonically reloads and revalidates the full verified Terraform/apply/
  inventory/trust/readiness, deploy context/original/effective/host-evidence-
  reconciled plan, prerequisite, pre-mutation evidence, immutable base-OS
  authorization, source, catalog, toolchain, and unchanged
  `IN_PROGRESS/VERIFY` journal chain. Exact authorized mapping-position-three
  `base-os` instances are expanded only in deterministic authorization order.
  Stable-ID limits, typed Ubuntu 24.04/image-architecture variables, and
  guest-architecture parity are derived from canonical inventory, desired image
  filters, and complete pre-mutation evidence, then rebuilt through the existing
  anchored command builder and controlled service.
  The independently versioned owner-only
  `deploy-scylla-vms.ansible-deploy-base-os-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-base-os-evidence/v1` records belong only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-base-os-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-base-os-evidence.json`.
  Each exact scope is first durably `prepared`; after complete revalidation it
  is durably `started` immediately before its one runner call. That started
  record, rather than a rewrite of immutable authorization, is the
  authorization-consumption boundary. Strict base-OS schema, exact target
  membership, Ubuntu/version/architecture parity, applied/changed/reboot and
  timesync policy outcomes, and provenance validation produce address-free
  semantic evidence before terminal state. Exit zero alone is insufficient.
  Once started, crash, timeout, interruption, nonzero, unreachable, non-UTF-8,
  oversized or malformed result, state drift, or post-invocation persistence
  failure is permanently manual-recovery-required and never automatically
  retried. An exact prepared prefix may resume because no call could have
  occurred; exact completed re-entry is zero-process. The strict report exposes
  only schemas/digests, authorization consumption, bounded scope/stable-ID/
  invocation/changed/reboot counts, retry/recovery/reboot flags, and unchanged
  journal status/phase.
  This owner never reboots, rolls back packages, restores images, updates the
  effective plan, invokes another playbook, finalizes deploy, changes the common
  journal, or adds CLI/public wiring. Result reconciliation belongs to the
  separate status below; reboot execution/reconnection, every later deploy
  stage, finalization, and the public workflow remain pending, so Phase 4 is not
  complete.
- **Deploy post-base-OS result reconciliation status (26.9.1):** this next
  narrow Phase 4 slice is complete as internal
  `reconcile_deploy_base_os_result`. Its only caller inputs are canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. It accepts no caller result, status, step, target, variable,
  command, path, runner, executable, or toolchain. Before persistence it
  canonically reloads and revalidates the unchanged `IN_PROGRESS/VERIFY`
  journal; complete verified Terraform/apply/inventory/trust/readiness chain;
  deploy context, original/effective/host-evidence-reconciled plans;
  prerequisite and pre-mutation evidence; immutable base-OS authorization,
  execution, and semantic evidence; packaged source; and catalog.
  Reconciliation requires exact terminal-success execution and complete unique
  evidence for every authorized stable ID. Prepared, started, failed,
  uncertain, manual-recovery, missing, extra, duplicate, wrong-host, mixed,
  stale, or provenance-drifted state fails before persistence. The owner
  recomputes the complete 21-position mapping and preserves every expanded
  sequence, condition, classification, target, limit, serial, check-mode,
  variable, source, command, and original-step digest.
  The independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-base-os-reconciliation/v1` companion belongs
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-base-os-reconciliation.json`.
  Exact authorized `base-os` instances become evidence-bound `succeeded` only
  after exact applied/current success for all selected hosts. Changed and
  already-current outcomes are retained as bounded evidence counts, not treated
  as failures. Earlier inventory-preflight/connectivity success remains bound
  to its original semantic evidence.
  If any selected host reports reboot required, the companion records
  `reboot-required` and `reboot-handling-not-performed`, leaves reboot handling
  `not-performed`, and blocks every later active step. It never reboots,
  reconnects, authorizes, or invokes a process. With no reboot required, it
  evaluates only the exact next ordered mapping gate using facts that strict
  base-OS evidence explicitly supersedes plus independently current canonical
  readiness/trust evidence. A mutating next step may become only
  `evidence-ready-authorization-required`; a read-only next step may become
  `eligible` only when every independent gate is current. In the current
  jump-host path this can advance only the next `jump-host-configure` instance.
  No later mapping position is leapfrogged. Unexecuted `base-os` scopes and all
  later storage/package/configuration/bootstrap/health/quorum/Manager/
  monitoring/public-orchestration gates remain blocked or not performed, and
  final mapped `evidence-collect` remains `not-performed`. Pre-mutation host
  facts are not promoted across the mutation boundary except where strict
  base-OS result fields supersede them; unknown remains unknown.
  Validation and record construction complete in memory before atomic
  owner-only no-follow persistence. Exact unchanged re-entry is zero-write;
  conflicting artifacts are never overwritten, deleted, rolled back, or
  adapted. The strict
  `deploy-scylla-vms.ansible-deploy-base-os-reconciliation-report/v1`
  projection contains only schemas/digests, step-status and changed/current/
  reboot counts, explicit reboot state, grouped next authorization-required or
  eligible playbook-instance/stable-ID counts and digests, blocker enums/digest,
  and journal status/phase. It contains no addresses, provider IDs, routes,
  keys, commands, variables, environment, paths, raw evidence, credentials, or
  secrets. This slice creates no authorization/execution intent, runner or
  toolchain call, journal transition, reboot, finalization, CLI, or public
  workflow. Reboot execution/reconnection, next-step authorization/execution,
  every later stage, finalization, and public deploy remain pending, so Phase 4
  is not complete.
- **Deploy reboot plan/authorization status (26.9.2):** this planning-only
  Phase 4 slice is complete as internal
  `plan_and_authorize_deploy_reboots`. Its only inputs are canonical state-root/
  cluster identity, one operation UUID, the matching already-held deploy lock,
  and an optional already-normalized ordinary approval proof. Caller targets,
  order, commands, variables, paths, classification, reboot policy, free-form
  text, runners, executables, and toolchains are forbidden.
  Before persistence it canonically reloads and revalidates the unchanged
  `IN_PROGRESS/VERIFY` journal, complete verified Terraform/apply/inventory/
  trust/readiness chain, deploy context/original/effective/host-evidence-
  reconciled plans, prerequisite/connectivity and pre-mutation evidence,
  immutable base-OS authorization/execution/semantic evidence and post-base-OS
  reconciliation, packaged source, and catalog. Reboot targets derive only
  from successful exact base-OS semantic evidence whose strict result reports
  `reboot-required`; counts and stable IDs must exactly match reconciliation.
  No-reboot state returns strict `not-required`, accepts no proof, creates no
  reboot artifacts, and leaves the existing no-reboot next-step status
  undisturbed.
  For reboot-required state, the independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-reboot-plan/v1` record belongs only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-reboot-plan.json`.
  It preserves exact successful base-OS execution order with stable-ID
  tie-breaking, serial one, exact role batches, current inventory/trust/route
  and complete connectivity evidence, source/catalog assumptions, and
  address-free target/order/route-dependency digests. A routed host may not
  precede a selected jump dependency. Incomplete connectivity, unknown role or
  order, missing jump dependency, or unsafe jump ordering persists a blocked
  plan with stable `connectivity-evidence-incomplete`,
  `reboot-order-unresolved`, `jump-route-dependency-unresolved`, or
  `jump-route-order-unresolved` blockers and creates no authorization.
  Every target requires a future post-reboot reconnect, exact current
  identity/trust revalidation, machine evidence, and strict base-OS
  reboot-clear verification before the next serial target. Those checkpoints
  remain `not-performed`.
  Reboot handling within the `deploy` operation is mutating. Only ordinary
  interactive approval or PLAN-permitted `--yes` may authorize the exact ready
  plan; absent or denied approval fails closed, and destructive flags/scope
  proof are inapplicable. The separate immutable owner-only
  `deploy-scylla-vms.ansible-deploy-reboot-authorization/v1` record belongs only
  at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-reboot-authorization.json`
  and binds the exact plan artifact and record, ordered target/role batches,
  classification, serial/checkpoint policy, blocker-free state, normalized
  proof digest, and complete provenance. Persistence order is plan then
  authorization. Exact records are reusable, a plan-only prefix may recover
  authorization, and changed evidence/order/proof/state conflicts never
  overwrite, delete, roll back, or adapt the operation.
  The strict
  `deploy-scylla-vms.ansible-deploy-reboot-plan-authorization-report/v1`
  projection retains only schemas/digests, bounded target/role counts, order
  and role-batch digests, serial/checkpoint policy, classification, normalized
  approval method/state, blocker enums/digest, and unchanged journal status/
  phase. It contains no addresses, provider IDs, routes, keys, commands,
  variables, environment, paths, raw evidence, prompts, credentials, or
  secrets. At this planning boundary authorization remains unconsumed,
  execution and reconnect are not performed, and the common journal and
  deploy-step reconciliations remain byte-for-byte unchanged. This owner
  invokes no process, performs no reboot or reconnect, creates no execution
  record, advances no later deploy step, and adds no CLI/public wiring. The
  separately reviewed execution owner below consumes the exact authorization;
  post-reboot deploy-plan reconciliation, later stages, finalization, and
  public deploy remain pending, so Phase 4 is not complete.
- **Deploy reboot execution/evidence status (26.9.3):** this narrow Phase 4
  slice is complete as internal `execute_deploy_reboots`. Its only inputs are
  canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, the controlled runner, and an exact validated
  sibling Ansible executable/toolchain dependency. Caller targets, order,
  limits, variables, playbooks, paths, commands, environments, results, and
  retry controls are forbidden.
  Before every effect it canonically reloads and recomputes the unchanged
  `IN_PROGRESS/VERIFY` journal; verified Terraform/apply/inventory/trust/
  readiness chain; deploy context, original/effective/host-evidence/base-OS
  reconciliations; prerequisite/connectivity and pre-mutation evidence;
  immutable base-OS authorization/execution/evidence; exact reboot plan and
  unconsumed authorization; packaged source; catalog; and toolchain identity.
  It refuses blocked or reordered plans, stale trust/readiness/connectivity,
  missing reboot proof, unsafe role/platform/service evidence, changed
  authorization, ambiguous artifacts, or any uncertain execution prefix
  before a process call.
  The distinct hash-checked `deploy-reboot` support source is Ubuntu-24.04-only,
  exact-one-target, serial-one/fatal, and check-mode-refused. It accepts only
  the owner-derived typed request, uses no shell or arbitrary command, checks
  fixed role-specific inactive service gates, hashes the pre-boot boot ID only
  in memory, and invokes bounded `ansible.builtin.reboot`. After reconnect it
  requires strict host-key checking, a changed boot identity, exact stable
  host/OS/version/architecture parity, current service safety, and absent
  `/var/run/reboot-required`. Its independently versioned strict
  `deploy-scylla-vms.ansible-deploy-reboot/v1` result contains only bounded
  enums, booleans, elapsed time, and request identity; it omits raw boot IDs,
  addresses, provider IDs, routes, keys, facts, commands, environment, service
  output, credentials, secrets, and raw module output.
  Persist owner-only
  `deploy-scylla-vms.ansible-deploy-reboot-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-reboot-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-reboot-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-reboot-evidence.json`.
  Their independently versioned binding and evidence-entry schemas bind the
  operation/journal, exact plan/authorization, base-OS execution/evidence/
  reconciliation, connectivity, inventory, trust, readiness, source/catalog,
  executable/toolchain, ordered target set, and per-target plan/variable/
  command/request/result/evidence digests.
  Execute targets only in immutable plan order. Persist `prepared` before any
  invocation and `started` immediately before the sole controlled call; the
  first durable `started` consumes authorization for the whole ordered scope.
  Persist strict semantic evidence before terminal success. A succeeded prefix
  may continue only with the next exact target after complete reconnect,
  identity, trust, machine-evidence, boot-change, service-safety, and
  reboot-clear evidence for every prior target. Exact complete re-entry makes
  zero process calls.
  Once `started` is durable, crash, timeout, interruption, unreachable/nonzero
  execution, non-UTF-8/oversized/malformed output, changed boot/OS/
  architecture/identity/trust/service/reboot-clear evidence, post-call drift,
  or persistence failure is uncertain, manual-recovery-required, and
  permanently no-retry. Re-entry never reboots that target, skips it,
  continues to a later target, rolls back, or rewrites trust.
  Complete success reports `post-reboot-evidence-ready` while leaving the
  immutable reboot plan/authorization, deploy-step reconciliations, and common
  journal unchanged at `IN_PROGRESS/VERIFY`. This owner does not run general
  connectivity or host-evidence collection, reconcile post-reboot deploy
  steps, authorize later work, invoke Terraform/OCI, finalize deploy, or add
  CLI/public wiring.
- **Deploy post-reboot plan reconciliation status (26.9.3):** this narrow
  Phase 4 slice is complete as internal
  `reconcile_deploy_post_reboot_plan`. Its only inputs are canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. It accepts no caller status, target, order, result, step,
  variable, command, path, runner, executable, or toolchain.
  Before persistence it canonically reloads and revalidates the unchanged
  `IN_PROGRESS/VERIFY` journal; complete verified Terraform/apply/inventory/
  trust/readiness chain; deploy context, original/effective/host-evidence/
  base-OS reconciled plans; prerequisite/connectivity and pre-mutation evidence;
  immutable base-OS authorization/execution/semantic evidence; packaged source;
  and catalog. The no-reboot branch requires every reboot artifact to remain
  absent, records reboot handling as `not-required`, and preserves the already
  proven immediate next gate.
  The reboot-required branch reconstructs the exact immutable reboot plan,
  authorization, per-target variables and command intent, and execution binding.
  It requires terminal `succeeded` execution for the complete ordered target
  set, exact authorization consumption, one successful attempt and semantic
  entry per target, no uncertainty or recovery, and true service-safe-before,
  reboot-performed, reconnect, boot-changed, identity, trust, machine,
  service-safe-after, and reboot-clear gates. Missing, partial, extra,
  duplicate, reordered, wrong-target, started, failed, uncertain, stale,
  drifted, or mismatched evidence fails before persistence.
  The independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-reboot-reconciliation/v1` companion
  belongs only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-reboot-reconciliation.json`.
  It recomputes the complete documented deploy mapping while preserving every
  prior sequence, condition, classification, target, policy, variable, source,
  command, and step identity. Base-OS successes remain evidence-bound. Complete
  reboot proof changes reboot handling to evidence-bound `succeeded` and clears
  only `reboot-required` and `reboot-handling-not-performed`. Only the immediate
  proven mapping-position-four `jump-host-configure` instance may become
  `evidence-ready-authorization-required`; it is never execution-eligible.
  Pre-reboot connectivity and host evidence are retained only as provenance;
  post-reboot reconnect evidence supersedes only its explicit reboot, identity,
  trust, machine, service, and reboot-clear fields. Every other active scope and
  all storage/package/configuration/bootstrap/health/Manager/monitoring/final-
  evidence/public-orchestration work remains blocked or not performed.
  Validation and record construction complete in memory before atomic
  owner-only no-follow persistence. Exact unchanged re-entry is zero-write and
  every conflicting companion fails closed without overwrite, deletion,
  rollback, or adaptation. The strict
  `deploy-scylla-vms.ansible-deploy-post-reboot-reconciliation-report/v1`
  projection retains only the branch/status, bounded reboot/semantic and next-
  authorization counts, target set/order and next-target digests, blocker
  enums/digest, artifact/provenance digests, and unchanged journal status/phase.
  It omits boot IDs, addresses, provider IDs, routes, keys, commands, variables,
  environment, paths, raw evidence, credentials, and secrets. This owner creates
  no next-step authorization or execution record, invokes no runner/toolchain,
  changes no journal or earlier companion, reboots no host, finalizes nothing,
  and adds no CLI/public wiring. Next-step authorization/execution, every later
  deploy stage, finalization, and public deploy remain pending, so Phase 4 is
  not complete.
- **Deploy jump-host configuration authorization status (26.9.4):** this narrow
  Phase 4 slice is complete as internal
  `authorize_deploy_jump_host_configure`. Its only caller inputs are canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, and an already-normalized ordinary approval proof. Caller steps,
  playbooks, targets, limits, variables, commands, paths, classification,
  scope, destructive consent, and free-form text are forbidden.
  Before persistence it canonically reloads and revalidates the unchanged
  `IN_PROGRESS/VERIFY` journal; full verified Terraform/apply/inventory/trust/
  readiness chain; deploy context and original/effective/host-evidence/base-OS/
  post-reboot reconciliations; prerequisite, pre-mutation, base-OS, and
  branch-appropriate reboot authorization/execution/semantic evidence; current
  packaged source; and catalog. It reconstructs the exact post-reboot record
  and derives every authorizable instance and stable ID only from status
  `evidence-ready-authorization-required`. Only active mutating
  mapping-position-four `jump-host-configure` instances targeting canonical
  jump-host inventory identities are accepted; no broader, narrower, missing,
  extra, wrong-role, wrong-step, stale, uncertain, or drifted scope is
  authorizable.
  Ordinary interactive approval and PLAN-permitted `--yes` are the only proof
  methods. Neither bypasses exact cluster/host identity, inventory routes, SSH
  trust, machine readiness, base-OS/reboot evidence, deterministic
  configuration intent, or drift checks. Destructive flags/scope proof and
  storage-wipe/replacement/decommission/bootstrap consent are rejected as
  inapplicable.
  The independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-authorization/v1`
  companion belongs only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-jump-host-configure-authorization.json`.
  It binds the exact post-reboot reconciliation and deploy context/plans,
  prerequisite/host/base-OS/reboot evidence, inventory/trust/readiness,
  source/catalog/journal, every selected step sequence and source/command/
  target/variable/evidence digest, stable-ID count/set digest, mutating
  classification, and normalized proof method/digest. Exact unchanged reuse is
  zero-write. Changed proof, scope, chain, or provenance fails closed and
  requires a new operation rather than overwrite or adaptation.
  The strict
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-authorization-report/v1`
  projection retains only schemas/digests, approval method/state, mutating
  classification, playbook-instance and target counts/set digest,
  `consumed=false`, execution/finalization/public-workflow unavailable states,
  the non-authorized-step blocker digest, and unchanged journal status/phase.
  It omits addresses, provider IDs, routes, keys, fingerprints, configuration
  text, commands, variables, environments, paths, prompts, credentials, and
  secrets. This owner creates no execution record or intent, invokes no runner
  or toolchain, consumes no authorization, changes no step or journal state,
  finalizes nothing, and adds no CLI/public wiring. Exact jump-host
  configuration execution is separately owned by the next slice; all later
  deploy stages remain pending, so Phase 4 is not complete.
- **Deploy jump-host configuration execution status (26.9.4):** this narrow
  Phase 4 slice is complete as internal
  `execute_deploy_jump_host_configure`. Its only caller inputs are canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling
  `ansible-playbook`/`ansible-inventory` pair with its explicit supported
  toolchain dependency. Caller steps, playbooks, targets, limits, variables,
  paths, commands, environment, authorization, results, and loop controls are
  forbidden.
  Before every effect it canonically reloads and reconstructs the complete
  post-reboot reconciliation and immutable jump-host authorization plus the full
  Terraform-to-readiness/deploy/base-OS/reboot chain, current connectivity,
  observation/inventory/trust and strict derivatives, rendered controller
  files, packaged source, catalog, toolchain, and unchanged
  `IN_PROGRESS/VERIFY` journal. It derives only ordered active mutating
  mapping-position-four `jump-host-configure` instances, requires exact-one
  canonical jump stable ID per serial call, and derives the role-level
  configuration authorization, RFC 1918 PermitOpen route set, rendered hardening
  policy, typed runtime payload, source digest, and anchored command internally.
  Missing, broader, narrower, duplicate, stale, consumed, uncertain, or drifted
  scope fails before invocation.
  The independently versioned generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-evidence/v1` companions
  belong only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-jump-host-configure-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-jump-host-configure-evidence.json`.
  Execution records retry-safe `prepared`, then durable `started` immediately
  before each exact call. The first started record represents immutable
  authorization consumption without rewriting the authorization. Strict parsing
  must prove the result schema, selected stable ID, canonical observation/
  inventory/trust/base-OS/reboot/configuration authorization/source bindings,
  policy/route/configuration digests, validation success, and exact changed/
  reload consistency; exit zero alone is insufficient. Semantic evidence is
  persisted before terminal success and retains only bounded status and stable
  ID, changed/applied/validation/reload/restoration truth, and policy/route/
  config/configuration-authorization/result/source/evidence digests.
  The role's bounded internal restore behavior is not promoted into retry proof:
  successful results record restore `not-required`, while failed results record
  restore `not-proven`.
  Once started, crash, timeout, interruption, unreachable/nonzero execution,
  malformed/non-UTF-8/oversized output, missing/extra/duplicate/wrong target,
  identity/trust/policy/route/config mismatch, sshd validation/reload failure,
  post-call drift, or persistence failure is permanently
  manual-recovery/no-retry. Never skip, continue, rewrite trust, bypass host-key
  checking, or blindly reapply. Exact prepared recovery is allowed only before
  invocation, an exact succeeded prefix may continue, and complete exact
  re-entry performs zero tool calls.
  The strict
  `deploy-scylla-vms.ansible-deploy-jump-host-configure-execution-report/v1`
  projection retains only schemas/digests, authorization-consumed truth,
  execution/artifact state, invocation and target counts/set digest, changed/
  reload/restore counts, retry/recovery flags, and unchanged journal status/
  phase. Addresses, provider IDs, routes, configuration text, keys,
  fingerprints, commands, variables, environment, paths, raw output,
  credentials, and secrets remain absent. This owner does not rewrite the
  authorization or prior reconciliations, change any deploy-step status or
  journal event, rerun connectivity, execute another playbook, reconcile the
  next plan, finalize, or add CLI/public wiring. Jump-host result
  reconciliation and every later deploy stage remain pending, so Phase 4 is not
  complete.
- **Deploy post-jump-host result reconciliation status (26.9.5):** this narrow
  Phase 4 slice is complete as internal
  `reconcile_deploy_jump_host_configure_result`. Its only inputs are canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. Caller results, statuses, steps, targets, variables, commands,
  paths, runners, executables, and toolchains are forbidden.
  Before persistence it canonically reloads and revalidates the unchanged
  `IN_PROGRESS/VERIFY` journal; full verified Terraform/apply/inventory/trust/
  readiness chain; deploy context and original/effective/host-evidence/base-OS/
  post-reboot reconciliations; prerequisite/connectivity, pre-mutation,
  base-OS, branch-appropriate reboot, and jump-host authorization/execution/
  semantic evidence; current observation/inventory/trust/readiness and
  deterministic route/configuration intent; packaged source; and catalog.
  It reconstructs every authorized jump scope, typed variable digest, source
  and command intent, policy, PermitOpen route set, rendered configuration
  digest, and role-level configuration authorization from canonical state.
  Execution must be terminal `succeeded`, authorization consumed by durable
  execution intent, and complete for the exact unique authorized target set.
  Each semantic entry must prove the exact target and provenance, applied
  changed or no-change status, successful sshd validation, reload performed
  and passed exactly when changed, no blockers, and restoration unambiguously
  `not-required`. Prepared, started, failed, unreachable, timed-out,
  interrupted, malformed, uncertain, manual-recovery, retryable, missing,
  extra, duplicate, wrong-target, validation/reload/restore-ambiguous,
  policy/route/configuration-mismatched, stale, or drifted state fails before
  persistence.
  The independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-jump-host-configure-reconciliation/v1`
  companion belongs only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-jump-host-configure-reconciliation.json`.
  It recomputes the exact documented mapping and preserves every sequence,
  condition, classification, target, limit/check/serial policy, variable,
  source, command, original-step, and prior-reconciled-step identity. Exact
  jump-host configuration instances become evidence-bound `succeeded`; changed
  and no-change remain separate bounded evidence. It derives the first
  remaining active mapping rather than naming a fixed successor. Only that
  mapping may become read-only `eligible` or mutating
  `evidence-ready-authorization-required` when its exact independent gates are
  fully proven. In the current mapping this advances only final-routes
  `connectivity-check`; if all earlier mappings are inactive, non-jump
  `base-os` may advance only from unaffected current host evidence. Jump-host
  pre-mutation facts are never promoted across the jump mutation except for
  exact result evidence. Every storage/package/configuration/bootstrap/health/
  Manager/monitoring/final-evidence/public stage remains blocked or not
  performed, and no later step leapfrogs the immediate gate.
  Validation and record construction complete in memory before atomic
  owner-only no-follow persistence. Exact unchanged re-entry is zero-write and
  conflicts never overwrite, delete, roll back, or adapt prior records. The
  strict
  `deploy-scylla-vms.ansible-deploy-post-jump-host-configure-reconciliation-report/v1`
  projection retains only schemas/digests, bounded jump target/changed/
  no-change/validated/reload and step-status counts, next playbook/role/
  classification/status/target counts and set digests, blocker enums/digest,
  and unchanged journal status/phase. It omits addresses, provider IDs, routes,
  configuration content, keys, fingerprints, commands, variable values,
  environment, paths, raw evidence, credentials, and secrets.
  This owner invokes no runner/toolchain, creates no authorization or execution
  intent, changes no journal or earlier companion, rewrites no trust, finalizes
  nothing, and adds no CLI/public wiring. Final-routes connectivity execution
  and reconciliation, subsequent non-jump `base-os` authorization/execution,
  every later deploy stage, finalization, and public deploy remain pending, so
  Phase 4 is not complete.
- **Deploy final-routes connectivity status (26.9.5):** this narrow Phase 4
  execution, semantic-evidence, and reconciliation slice is complete as
  internal `execute_deploy_final_routes_connectivity` followed by
  `reconcile_deploy_final_routes_connectivity`. The execution owner accepts
  only canonical state-root/cluster identity, one operation UUID, the matching
  already-held deploy lock, a controlled runner, and an exact validated sibling
  Ansible executable/toolchain dependency. Caller playbooks, steps, targets,
  limits, destination hosts/roles/ports, variables, paths, commands,
  environments, results, and statuses are forbidden.
  Before every effect it canonically reloads and revalidates the unchanged
  `IN_PROGRESS/VERIFY` journal; full verified Terraform/apply/inventory/trust/
  readiness chain; deploy context and original/effective/host-evidence/base-OS/
  post-reboot/post-jump-host reconciliations; prerequisite and initial
  connectivity evidence; base-OS/reboot/jump-host authorization/execution/
  semantic evidence; current observation/inventory/trust/readiness and strict
  derivatives; packaged source; and catalog. It derives the one exact eligible
  mapping-position final-routes `connectivity-check`, selected jump stable IDs,
  and destination role/port pairs from immutable mapping and canonical assigned
  routes. Destination endpoints must be RFC 1918 inventory identities and each
  role/port must be in the documented allowlist. Public destinations, direct
  private-host SSH, arbitrary scanning, unknown roles/ports, and unassigned
  routes fail before invocation.
  It rebuilds only the anchored connectivity command with canonical controller
  paths, strict host-key checking, exact stable-ID limits, typed route probes,
  bounded process policy, and no caller tags, extra variables, callbacks,
  plugins, or environment. Owner-only
  `deploy-scylla-vms.ansible-deploy-final-routes-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-final-routes-evidence/v1` companions belong
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-final-routes-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-final-routes-evidence.json`.
  Durable `started` intent precedes the sole runner call. Strict output must
  prove exact source/result/step/command identity, one unique SSH outcome per
  selected jump, one unique outcome per requested destination role/port pair,
  no missing/extra/duplicate/wrong host or pair, and success for every required
  outcome; exit zero alone is insufficient. Evidence retains only stable jump
  IDs, role/port pairs, bounded status/counts, and provenance/set/request/result
  digests. Addresses, provider IDs, routes, keys, raw output, commands,
  variables, environment, protected paths, credentials, and secrets remain
  absent.
  Every started crash, timeout, interruption, unreachable/nonzero result,
  malformed/non-UTF-8/oversized output, semantic mismatch, post-call drift, or
  persistence failure is manual-recovery/no-retry. Exact complete success
  re-entry is zero-process; conflicting and uncertain prefixes fail closed.
  The separate reconciliation owner accepts only canonical operation identity
  and the held deploy lock, requires exact certain execution and semantic
  evidence, and persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-final-routes-reconciliation/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-final-routes-reconciliation.json`.
  It marks only the exact final-routes instance evidence-bound `succeeded`,
  recomputes the complete mapping, and evaluates only the immediate next active
  gate. In the current mapping non-jump `base-os` may become
  `evidence-ready-authorization-required` only when all unaffected independent
  evidence remains current; every later storage/package/configuration/
  bootstrap/health/Manager/monitoring/final-evidence stage stays blocked or
  not performed. No gate is hard-coded or leapfrogged.
  Strict execution and reconciliation reports expose only schemas/digests,
  invocation/execution state, jump/pair counts and set digests, bounded step
  status and next-gate playbook/role/target counts, blocker enums, retry/
  recovery truth, and unchanged journal status/phase. This slice creates no
  authorization, executes no mutation, changes no journal or prior companion,
  invokes no Terraform/OCI/SSH scanner, finalizes nothing, and adds no CLI or
  public workflow wiring. Next non-jump `base-os` execution/reconciliation and
  all later deploy stages remain pending, so Phase 4 is not complete.
- **Deploy post-final-routes non-jump base-OS authorization status (26.9.6):**
  this narrow Phase 4 ordinary-authorization slice is complete as internal
  `authorize_deploy_non_jump_base_os`. It accepts only canonical state-root and
  cluster identity, one operation UUID, the matching already-held deploy lock,
  and an already-normalized ordinary approval proof. Caller steps, targets,
  roles, limits, variables, commands, paths, classifications, scopes, prompts,
  and free-form text are forbidden.
  Before persistence it canonically reloads and revalidates the unchanged
  `IN_PROGRESS/VERIFY` journal; full verified Terraform/apply/inventory/trust/
  readiness chain; deploy context and original/effective/host-evidence/base-OS/
  post-reboot/post-jump-host/post-final-routes reconciliations; prerequisite,
  pre-mutation host, base-OS, reboot, jump-host, and final-routes execution and
  semantic evidence; current inventory/trust/readiness derivatives; packaged
  source; and catalog. It requires certain terminal final-routes success and
  recomputes the immutable post-final-routes record before deriving scope.
  Only active mutating mapping-position-six `base-os` with condition
  `non-jump-managed-hosts`, target role `all`, and status
  `evidence-ready-authorization-required` is authorizable. Its exact sorted
  stable-ID set must equal all canonical non-jump managed hosts, remain
  disjoint from the earlier immutable jump-scope base-OS authorization, and
  retain exact step sequence/source/command/variable/target, final-routes
  evidence, and pre-mutation host-evidence identities. Jump, extra, missing,
  wrong, inactive, non-ready, previously authorized, ambiguous, broadened, or
  drifted scope and uncertain execution history fail before persistence.
  Classification is always mutating. The only accepted proof methods are
  ordinary interactive approval and PLAN-permitted `cli-yes`; both remain
  subordinate to every identity, route/connectivity, trust, readiness, host
  evidence, reboot, ordering, and drift gate. Denied, missing, malformed,
  destructive-class, destructive-scope, and narrow-consent proofs are refused
  as inapplicable.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-base-os-authorization.json`.
  This path and schema are distinct from the already completed
  `<operation-uuid>.ansible-deploy-base-os-authorization.json`; the earlier
  authorization, execution, evidence, and reconciliation remain byte-for-byte
  immutable. The new record binds stage/scope identity, exact step and target
  digests, final-routes execution/evidence/reconciliation, host evidence, and
  complete upstream provenance. Atomic no-follow owner-only persistence allows
  exact zero-write reuse; changed proof, scope, or state fails closed without
  overwrite, deletion, rollback, or adaptation. Authorization remains
  unconsumed until a later reviewed durable started execution record.
  The strict
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-authorization-report/v1`
  projection retains only schemas/digests, stage/scope, ordinary approval
  method/state, playbook/role/target counts and set digests, blocker digest,
  `consumed=false`, execution unavailable, and unchanged journal status/phase.
  It omits target identities, addresses, provider IDs, routes, keys,
  fingerprints, commands, variable values, environment, paths, prompts,
  credentials, and secrets. This owner invokes no runner or toolchain, creates
  no execution record or step-status mutation, advances no journal, finalizes
  nothing, and adds no CLI/public wiring. Non-jump base-OS execution,
  reconciliation, reboot handling, storage/package/configuration/bootstrap/
  health/Manager/monitoring stages, finalization, and public deploy remain
  pending, so Phase 4 is not complete.
- **Deploy post-final-routes non-jump base-OS execution status (26.9.7):**
  this narrow Phase 4 execution and semantic-evidence slice is complete as
  internal `execute_deploy_non_jump_base_os`. Its API accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling
  `ansible-playbook`/`ansible-inventory` pair with its supported toolchain
  dependency. Caller steps, playbooks, targets, limits, variables, paths,
  commands, environments, authorizations, results, and loop controls are
  absent.
  Before every effect the owner canonically reloads and revalidates the complete
  verified Terraform/apply/inventory/trust/readiness chain; deploy context and
  original/effective/host-evidence/base-OS/post-reboot/post-jump-host/
  post-final-routes reconciliations; prerequisite, pre-mutation, base-OS,
  reboot, jump-host, and final-routes execution/evidence; current inventory,
  trust, readiness, connectivity, source, catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal; and the distinct immutable non-jump
  authorization. It recomputes that authorization from the current chain and
  requires its original unconsumed `authorized-pre-execution` state.
  Execution derives only the exact active mapping-position-six `base-os`
  instance with condition `non-jump-managed-hosts`, sorted complete non-jump
  stable-ID scope, source, typed Ubuntu 24.04/image-architecture variables,
  guest/image architecture parity, and anchored command. Jump targets, overlap
  with the earlier jump-scope authorization, missing/extra/non-ready hosts,
  OS/architecture/reboot/service/capacity/route blockers, stale or consumed
  authorization, uncertain history, and provenance drift fail before
  invocation. The sole current instance retains the catalog serial-one policy
  and exact complete non-jump limit.
  Persist independently versioned generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-non-jump-base-os-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-base-os-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-base-os-evidence.json`.
  The owner records optional retry-safe `prepared`, then durable `started` with
  whole-scope authorization consumption immediately before the one controlled
  invocation. Authorization remains immutable and unmodified. The invocation
  uses canonical controller config/inventory/cwd, strict host-key checking,
  controlled environment, exact variables and limit, bounded timeout/output,
  strict UTF-8/redaction, and no arbitrary tags, extra variables, plugins,
  callbacks, or ambient environment.
  Exit zero is insufficient. Strict `base-os` parsing must return the exact
  schema and complete unique selected stable-ID set with no missing, extra,
  duplicate, or wrong host; exact Ubuntu/version/guest-image architecture and
  provenance parity; and coherent applied/changed/reboot-required/
  prerequisite-policy/timesync status. Evidence retains only stable IDs,
  bounded OS/version/architecture/status values, applied/changed/reboot flags,
  prerequisite/timesync statuses, and digests. Addresses, provider IDs,
  package or raw output, commands, variable values, environment, paths,
  credentials, and secrets are absent.
  Any uncertainty after started—including crash, timeout, interruption,
  failed/unreachable/nonzero or malformed/non-UTF-8/oversized result, semantic
  mismatch, post-call drift, and evidence or terminal persistence
  failure—requires manual recovery and permanently forbids automatic retry,
  replay, skip, continuation, reboot, or rollback. Exact prepared recovery is
  allowed only before invocation; exact succeeded-prefix recovery preserves
  deterministic order; complete re-entry makes zero process calls. Strict
  reports expose only schemas/digests, stage/scope, authorization consumption,
  execution/invocation/target/changed/reboot counts and set digests, retry/
  recovery truth, and unchanged journal status/phase.
  This slice changes no journal or prior artifact, performs no reconciliation
  or reboot handling, authorizes no next stage, finalizes nothing, and adds no
  CLI/public workflow wiring. Post-non-jump-base-OS result reconciliation,
  reboot planning/handling for this scope, storage/package/configuration/
  bootstrap/health/Manager/monitoring stages, finalization, and public deploy
  remain pending, so Phase 4 is not complete.
- **Deploy post-non-jump base-OS result reconciliation status (26.9.8):** this
  narrow Phase 4 subprocess-free reconciliation slice is complete as internal
  `reconcile_deploy_non_jump_base_os_result`. Its API accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. Caller statuses, results, steps, targets, paths,
  runners, executables, and toolchains are absent.
  Before persistence it canonically reloads and revalidates the unchanged
  `IN_PROGRESS/VERIFY` journal; full verified Terraform/apply/inventory/trust/
  readiness chain; deploy context and original/effective/host-evidence/
  base-OS/post-reboot/post-jump-host/post-final-routes reconciliations;
  prerequisite, pre-mutation, base-OS, reboot, jump-host, final-routes, and
  non-jump base-OS authorization/execution/semantic evidence; current
  inventory, trust, readiness, source, and catalog. It recomputes the exact
  immutable authorization and requires consumed execution authorization,
  terminal `succeeded`, all scopes completed, and one complete unique strict
  semantic result per exact authorized non-jump stable ID. Prepared, started,
  failed, timed-out, interrupted, unreachable, malformed, manual-recovery,
  retryable, missing, extra, duplicate, wrong-host, wrong-scope, mixed,
  stale, or provenance-drifted state fails before persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-non-jump-base-os-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-non-jump-base-os-reconciliation.json`.
  Recompute and preserve every mapping sequence, condition, classification,
  target, policy, variable, source, command, original-step, and prior-step
  identity. Mark only exact mapping-position-six
  `non-jump-managed-hosts` `base-os` instances distinctly evidence-bound
  `succeeded`; retain bounded changed, already-current, and reboot-required
  counts.
  If any non-jump target requires reboot, add explicit `reboot-required` and
  `reboot-handling-not-performed` blockers and keep every later active step
  blocked. Reboot handling remains `not-performed`; the owner neither creates a
  new reboot plan nor reuses the completed earlier jump-scope reboot
  plan/authorization/execution/evidence. If no reboot is required, derive the
  first remaining active mapping rather than naming a successor. Only that
  exact mapping may advance, and only when current inventory/trust/readiness/
  source/catalog and strict result evidence prove its independent gates.
  Read-only work may become `eligible`; mutating work may become only
  `evidence-ready-authorization-required`. In the current mapping this advances
  only the Scylla `storage-discover` scope. Storage preflight/preparation/write,
  package/configuration/bootstrap/health, Manager, monitoring, final evidence,
  finalization, and public stages remain blocked or not performed. Superseded
  pre-mutation OS/service fields are not promoted past the strict base-OS
  result, and no later gate leapfrogs storage discovery.
  Validation and record construction finish in memory before atomic owner-only
  no-follow persistence. Exact unchanged reuse is zero-write; conflicting
  records are never overwritten, deleted, rolled back, or adapted. The strict
  `deploy-scylla-vms.ansible-deploy-post-non-jump-base-os-reconciliation-report/v1`
  projection retains only schemas/digests, bounded scope/host/success/changed/
  already-current/reboot and next-gate playbook/role/target counts, blocker
  enums/digest, and unchanged journal status/phase. It omits addresses,
  provider IDs, routes, keys, commands, variable values, environment, paths,
  raw evidence, credentials, and secrets.
  This owner invokes no runner or external tool, creates no authorization,
  execution, reboot, storage, or finalization record, changes no prior
  companion or journal, and adds no CLI/public wiring. Non-jump reboot
  planning/handling or immediate storage-discovery execution and every later
  deploy stage remain pending, so Phase 4 is not complete.
- **Deploy non-jump reboot planning/authorization status (26.9.9):** this
  narrow Phase 4 subprocess-free slice is complete as internal
  `plan_and_authorize_deploy_non_jump_reboots`. Its API accepts only canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, and an optional already-normalized ordinary approval proof.
  Caller targets, order, routes, roles, commands, variables, paths,
  classification, execution controls, results, and free-form text are absent.
  Before any write it reloads and recomputes the complete verified Terraform/
  apply/inventory/trust/readiness and deploy chain through final-routes and
  exact post-non-jump-base-OS reconciliation. It derives reboot targets only
  from successful non-jump base-OS semantic results with
  `reboot_required=true`, requires exact count/scope parity with reconciliation,
  and refuses duplicate, missing, extra, wrong-role, jump-host, stale,
  malformed, uncertain, or provenance-drifted evidence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-plan/v1` then
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-authorization/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-reboot-plan.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-reboot-authorization.json`.
  These paths and schemas remain distinct from the earlier jump-scope reboot
  plan/authorization and never overwrite or reuse it. The plan preserves exact
  successful non-jump base-OS execution order with stable-ID tie-breaking,
  serial one, canonical jump-route dependencies, and current final-routes
  connectivity. It binds the post-non-jump reconciliation, non-jump
  authorization/execution/evidence, final-routes execution/evidence/
  reconciliation, inventory, trust, readiness, source, catalog, and unchanged
  `IN_PROGRESS/VERIFY` journal.
  Every target records mandatory future reconnect, identity/trust
  revalidation, machine evidence, role-service safety, and reboot-clear
  verification before the next target. Stable blockers cover incomplete
  final-routes connectivity, unresolved jump dependencies, and unresolved
  base-OS/reboot order. A blocked plan creates no authorization. Ordinary
  interactive or PLAN-permitted `cli-yes` approval is required for a ready
  mutating plan; denied, missing, changed, malformed, or destructive proof is
  refused. Authorization is bound to the exact plan artifact, target set and
  order, route relationship, and provenance digests.
  Plan persistence precedes proof validation and authorization persistence so
  an exact plan-only prefix can recover. Exact plan/authorization reuse is
  zero-write; changed scope, order, proof, evidence, or provenance requires a
  new operation. Conflicts never overwrite, delete, roll back, or adapt an
  artifact. If no reboot is required, the API accepts no proof, creates no
  artifact, returns strict `not-required`, and verifies that the independently
  reconciled Scylla `storage-discover` branch remains eligible.
  Strict reports retain only schemas, states, bounded target/role counts,
  blocker enums, future-gate booleans, and digests. Addresses, provider IDs,
  routes, keys, commands, variable values, environments, paths, raw evidence,
  credentials, and secrets are absent. Authorization remains unconsumed,
  execution and reconnect remain unavailable/not-performed, every prior
  artifact and the journal remain byte-for-byte unchanged, and no process is
  invoked. This planning/authorization boundary performs neither reboot
  execution nor post-reboot reconciliation. Post-reboot reconciliation,
  storage-discovery execution, later stages, finalization, CLI, and public
  wiring remain pending, so Phase 4 is not complete.
- **Deploy non-jump reboot execution status (26.9.10):** this narrow Phase 4
  controlled-execution slice is complete as internal
  `execute_deploy_non_jump_reboots`. Its API accepts only canonical state-root/
  cluster identity, one operation UUID, the matching already-held deploy lock,
  a controlled runner, and an exact validated sibling
  `ansible-playbook`/`ansible-inventory` pair with the explicit supported
  toolchain. Caller targets, order, limits, variables, playbooks, paths,
  commands, environments, results, and retry controls are absent.
  Before every effect it reloads and recomputes the complete verified
  Terraform/apply/inventory/trust/readiness and deploy chain through current
  final-routes evidence, successful non-jump base-OS semantic evidence and
  reconciliation, and the exact distinct non-jump reboot plan and unconsumed
  authorization. It derives only plan-ordered reboot-required non-jump targets,
  preserves exact base-OS execution order, validates route/trust/readiness/
  source/catalog/journal bindings, and constructs only the hash-checked
  `deploy-reboot` support-source invocation. The API probes no tool and creates
  no execution artifact when the independently reconciled no-reboot branch
  preserves `storage-discover`.
  Persist independently versioned generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-non-jump-reboot-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-reboot-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-non-jump-reboot-evidence.json`.
  These paths and schemas are distinct from every earlier jump-scope reboot
  artifact. For each serial-one target, persist retry-safe `prepared` intent
  and then durable `started` immediately before the sole controlled call. The
  first started record consumes the exact whole-scope non-jump authorization
  without rewriting it. Only a strict succeeded prefix may continue to the
  next immutable target.
  Accept only the strict `deploy-scylla-vms.ansible-deploy-reboot/v1` semantic
  result with exact target, role, request, command, source, Ubuntu 24.04,
  architecture, reconnect, changed boot identity, current trust, machine
  evidence, pre/post role-service safety, and absent reboot-required marker.
  Exit zero alone is insufficient. Persisted evidence retains only bounded
  statuses, elapsed time, stable ID/role/OS/architecture, gate booleans, and
  provenance/result/evidence digests. Raw boot IDs, addresses, provider IDs,
  routes, keys, commands, variables, environments, output, credentials,
  secrets, and protected paths are absent.
  Once started, crash, timeout, interruption, unreachable/nonzero execution,
  malformed/non-UTF-8/oversized output, semantic mismatch, post-call drift, or
  persistence failure is uncertain, manual-recovery-required, and permanently
  no-retry. The owner never reboots that target again automatically, skips it,
  continues, rolls back, or rewrites trust. An exact prepared prefix may resume
  because no invocation could have occurred; an exact succeeded prefix
  continues in immutable order; complete exact re-entry makes zero process
  calls. The immutable plan/authorization, earlier jump-scope artifacts,
  prior deploy companions, and common `IN_PROGRESS/VERIFY` journal remain
  unchanged. This slice does not reconcile post-reboot state, advance
  `storage-discover`, authorize later work, finalize deploy, or add CLI/public
  wiring. Post-reboot reconciliation and every later deploy stage remain
  pending, so Phase 4 is not complete.
- **Deploy post-non-jump-reboot reconciliation status (26.9.11):** this narrow
  Phase 4 subprocess-free reconciliation slice is complete as internal
  `reconcile_deploy_post_non_jump_reboot_plan`. Its API accepts only canonical
  state-root/cluster identity, one operation UUID, and the matching already-held
  deploy lock. It accepts no caller status, result, target, path, runner,
  executable, toolchain, command, variable, or retry control.
  Before persistence it canonically reloads and recomputes the complete
  verified Terraform/apply/inventory/trust/readiness and deploy chain through
  exact post-non-jump-base-OS reconciliation plus the distinct non-jump reboot
  plan/authorization/execution/evidence family. The no-reboot branch requires
  exact zero reboot candidates, the independently reconciled no-reboot state,
  and absence of every non-jump reboot artifact. The reboot-required branch
  requires the exact recomputed unblocked plan and authorization, exact target
  set and order, consumed execution authorization, terminal all-target success,
  no manual-recovery or retry ambiguity, and complete unique semantic evidence.
  Every target must prove successful invocation plus reconnect, changed boot
  identity, identity verification, current trust, machine evidence, pre/post
  service safety, and reboot-clear truth. Missing, partial, prepared, started,
  failed, unreachable, timed-out, interrupted, malformed, extra, duplicate,
  reordered, wrong-target, stale, drifted, or mismatched state fails before
  persistence.
  Persist independently versioned immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-non-jump-reboot-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-non-jump-reboot-reconciliation.json`.
  Recompute and preserve every mapping/step identity. No-reboot preserves the
  prior independently derived plan. Complete reboot proof clears only the
  reboot blockers and derives the first remaining active mapping rather than
  naming a successor. Only that immediate gate may advance; read-only work may
  become `eligible`, while mutating work may become only
  `evidence-ready-authorization-required`. In the current mapping this advances
  only Scylla `storage-discover`. Storage preflight/prepare/postcheck, package,
  configuration, bootstrap, health, Manager, monitoring, final evidence, and
  public/finalization work remain blocked or not performed.
  The strict report retains only schemas/digests, branch and bounded target/
  success/gate/next-step counts, safe playbook/role/class/status summaries,
  blocker enums/digest, and unchanged journal status/phase. It omits addresses,
  provider IDs, routes, keys, fingerprints, boot IDs, commands, variables,
  environments, paths, raw evidence, credentials, and secrets. Record
  construction completes in memory before atomic owner-only no-follow
  persistence. Exact unchanged reuse is zero-write; conflicts never overwrite,
  delete, roll back, or adapt. This owner invokes no runner or external tool,
  mutates no prior record or journal, creates no authorization or execution
  artifact, finalizes nothing, and adds no CLI/public deploy wiring.
- **Deploy storage-discovery execution/evidence and reconciliation status
  (26.9.12):** this narrow Phase 4 slice is complete as internal
  `execute_deploy_storage_discovery` and
  `reconcile_deploy_storage_discovery`. The execution API accepts only
  canonical state-root/cluster identity, one operation UUID, the matching held
  deploy lock, controlled runner, and exact validated sibling Ansible
  executable/toolchain dependency. It accepts no caller target, limit,
  playbook, variable, path, result, status, or retry control.
  Before every effect it canonically reloads and revalidates the full verified
  Terraform/apply/inventory/trust/readiness and deploy chain through exact
  post-non-jump-reboot reconciliation, then derives the sole eligible sorted
  Scylla stable-ID scope and command intent from immutable current records. It
  invokes only the catalog `storage-discover` source through the anchored
  controlled service with exact role, explicit stable-ID limit, serial-five
  policy, strict host-key checking, bounded timeout/output, and redaction.
  Generation-guarded owner-only
  `deploy-scylla-vms.ansible-deploy-storage-discovery-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-storage-discovery-evidence/v2` belong only
  at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-discovery-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-discovery-evidence.json`.
  Durable `started` intent precedes the sole call. Success requires strict
  schema/provenance and exact complete unique host and device evidence; exit
  zero alone is insufficient. Evidence retains only stable IDs, bounded
  statuses/counts, sizes, booleans, and hashed device/signature/ownership/
  topology identities. Raw device paths/serials, addresses, provider IDs,
  commands, variables, environments, output, credentials, and secrets remain
  absent. A started crash, timeout, interruption, nonzero/unreachable or
  malformed result, semantic mismatch, drift, or persistence uncertainty is
  permanent manual-recovery/no-retry and forbids skip or continuation. Exact
  complete re-entry makes zero process calls.
  Reconciliation canonically reloads the exact terminal execution/evidence and
  complete prior chain, then persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-storage-discovery-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-storage-discovery-reconciliation.json`.
  It marks only mapping-position-seven `storage-discover` succeeded and
  evaluates only the immediate next active mapping. Current mapping may make
  read-only Scylla `storage-preflight` eligible when all exact gates are
  proven; it never creates storage mutation authorization or leapfrogs
  preparation, postcheck, package, configuration, bootstrap, health, Manager,
  monitoring, final evidence, or public/finalization work. Exact reuse is
  zero-write; conflicts fail closed. Every prior artifact and the common
  `IN_PROGRESS/VERIFY` journal remain byte-for-byte unchanged. Storage
  preflight execution and every later stage remain pending, so Phase 4 is not
  complete.
- **Deploy storage-preflight execution/evidence and reconciliation status
  (26.9.13):** this narrow Phase 4 slice is complete as internal
  `execute_deploy_storage_preflight` and
  `reconcile_deploy_storage_preflight`. The execution owner accepts only
  canonical state-root/cluster identity, one operation UUID, the matching held
  deploy lock, controlled runner, and exact validated sibling Ansible
  executable/toolchain dependency. It canonically reloads the complete chain
  through exact post-storage-discovery reconciliation, then derives the sole
  eligible sorted Scylla stable-ID scope and typed desired-policy,
  Terraform-manifest, and discovery projection without caller targets,
  variables, commands, paths, results, statuses, or retry controls.
  It invokes only hash-checked catalog `storage-preflight`, with explicit
  stable-ID limit, serial-five/check-mode policy, strict host-key checking,
  bounded output/time, and redaction. Owner-only generation-guarded
  `deploy-scylla-vms.ansible-deploy-storage-preflight-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-storage-preflight-evidence/v1` belong only
  at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-preflight-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-preflight-evidence.json`.
  Durable `started` intent precedes the sole call. Success requires exact
  schema, provenance, complete unique host membership, and byte-equivalent
  semantic results; exit zero alone is insufficient. Evidence retains only
  stable IDs, bounded backend/layout/capacity, exact desired/manifest/discovery
  digests, disposition/action enums, hashed device sets, blocker/status
  digests, and preparation-intent digests. Addresses, provider IDs, device
  paths/serials, raw evidence/output, commands, variables, environments,
  credentials, and secrets remain absent. Every started crash, timeout,
  interruption, malformed/non-UTF-8/oversized/nonzero/unreachable result,
  membership/provenance drift, or persistence uncertainty is permanent
  manual-recovery/no-retry. Exact terminal re-entry makes zero process calls.
  Reconciliation reloads that exact terminal execution/evidence and full prior
  chain and persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-storage-preflight-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-storage-preflight-reconciliation.json`.
  It marks only exact mapping-position-eight `storage-preflight` succeeded.
  Blocked results remain blockers; `owned-noop` is explicitly not required and
  never rewritten or authorized. Only `prepare-required` hosts form the
  immediate `storage-prepare` authorization scope, bound to exact disposition,
  device-set, and preparation-intent digests. Wipe-required scope and digest
  remain separate for later explicit wipe consent. Exact reuse is zero-write,
  prefix recovery is fail-closed, and no storage mutation, authorization
  collection, runner call during reconciliation, later-gate leapfrog, journal
  transition, finalization, CLI, or public wiring is introduced. Phase 4
  remains incomplete after this slice.
- **Implementation status — dedicated storage preparation authorization
  (26.9.14):** this narrow follow-on Phase 4 slice is complete as internal
  `authorize_deploy_storage_prepare`. It accepts only canonical state-root and
  cluster identity, one operation UUID, the matching held deploy lock, one
  normalized typed general proof, and an optional normalized typed wipe proof.
  It reloads and revalidates the complete chain through exact immutable
  post-storage-preflight reconciliation, then derives only `prepare-required`
  mapping-position-nine hosts with exact stable-ID, action, disposition,
  device-set, preparation-intent, step, source, variable, command-intent, and
  evidence digests. `owned-noop` and blocked storage remain excluded.
  Every derived scope retains destructive classification and requires ordinary
  interactive or PLAN-permitted `cli-yes` approval plus explicit
  `--allow-destructive` and an exact address-free preparation count/target/scope
  proof. `cli-yes` alone is insufficient. Wipe consent uses a separate
  `deploy-scylla-vms.ansible-deploy-storage-prepare-wipe-proof/v1` decision,
  is required only for the exact wipe-required subset, and rejects absent,
  denied, extra, narrower, broader, non-wipe, or mismatched scope. The general
  destructive decision is independently versioned as
  `deploy-scylla-vms.ansible-deploy-storage-prepare-general-proof/v1`.
  The immutable owner-only
  `deploy-scylla-vms.ansible-deploy-storage-prepare-authorization/v1` belongs
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-prepare-authorization.json`.
  It binds original/current plan, semantic evidence, inventory, trust,
  readiness, source, catalog, journal, per-host authorization, and separate
  preparation/wipe scope digests. Exact reuse is zero-write and conflicts fail
  closed. The redacted
  `deploy-scylla-vms.ansible-deploy-storage-prepare-authorization-report/v1`
  exposes only bounded counts, digests, proof states, unchanged journal state,
  and unavailable execution. This authorization owner leaves authorization
  unconsumed; it introduces no runner, toolchain probe, execution record,
  storage mutation, postcheck, finalization, CLI, or public workflow wiring.
  Phase 4 remains incomplete after this slice.
- **Implementation status — durable storage preparation execution and semantic
  evidence (26.9.19):** this narrow follow-on Phase 4 slice is complete as
  internal `execute_deploy_storage_prepare`. Its only inputs are canonical
  state-root/cluster identity, one operation UUID, the matching already-held
  deploy lock, a controlled runner, and an exact validated sibling Ansible
  executable/toolchain dependency. It reloads and revalidates the complete
  chain through immutable post-storage-preflight reconciliation and exact
  destructive storage authorization, then derives only ordered
  `prepare-required` scopes with exact action, disposition, device-set,
  preparation-intent, source, variable, command-intent, and provenance
  digests. Blocked and `owned-noop` storage can never execute.
  The owner invokes only hash-checked catalog `storage-prepare`, exact one
  stable ID at a time, serial one, with check mode refused and internally
  constructed variables. It persists owner-only
  `deploy-scylla-vms.ansible-deploy-storage-prepare-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-storage-prepare-evidence/v1` only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-prepare-execution.json`
  and
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-storage-prepare-evidence.json`.
  Every attempt is durably `prepared`, then `started`, before the controlled
  call. The first started attempt consumes general authorization; a wipe proof
  is consumed only at the exact wipe-required target boundary. Strict ordered
  prefixes forbid replay, skip, broadening, or continuing after uncertainty.
  The packaged role now resolves public device-identity digests only during
  immediate pre-write revalidation and returns strict proof of exact action,
  disposition, device set, provenance, wipe application, mutation boundary,
  first irreversible step, completed state, and post-action verification.
  Exit zero alone is insufficient. Started crash, timeout, interruption,
  nonzero/unreachable, malformed/oversized result, state drift, or
  post-invocation persistence uncertainty is permanent
  manual-recovery/no-retry/no-skip/no-continue/no-rollback. Evidence and the
  redacted
  `deploy-scylla-vms.ansible-deploy-storage-prepare-execution-report/v1`
  omit addresses, provider IDs, device paths/serials, commands, variables,
  environment, raw output, credentials, and secrets. Exact completed re-entry
  is zero-process, the common journal remains byte-for-byte at
  `IN_PROGRESS/VERIFY`, and post-preparation reconciliation, storage postcheck,
  finalization, CLI, and public workflow wiring remain absent. Phase 4 remains
  incomplete after this slice.
- **Implementation status — immutable post-storage-prepare reconciliation
  (26.9.19):** this narrow follow-on Phase 4 slice is complete as internal
  `reconcile_deploy_storage_prepare`. Its only inputs are canonical
  state-root/cluster identity, one operation UUID, and the matching
  already-held deploy lock. It reloads and revalidates the full chain through
  post-storage-preflight reconciliation, exact storage authorization,
  preparation execution/evidence, discovery, inventory, trust, readiness,
  packaged source/catalog, and unchanged `IN_PROGRESS/VERIFY` journal.
  Every `prepare-required` target must have exact ordered terminal success,
  consumed general authorization, consumed wipe proof where required, matching
  action/disposition/device-set/preparation-intent/provenance, and no recovery
  uncertainty. Partial, started, failed, extra, mismatched, stale, drifted, or
  ambiguous state fails closed.
  The owner persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-storage-prepare-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-storage-prepare-reconciliation.json`.
  Exact prepare-required scopes become evidence-bound succeeded. Existing
  `owned-noop` scopes remain current and explicitly not mutated; blocked scopes
  remain blocked. Only the immediate exact read-only `storage-postcheck` scope
  may become eligible, while package installation and every later gate remain
  blocked or not performed. The redacted
  `deploy-scylla-vms.ansible-deploy-post-storage-prepare-reconciliation-report/v1`
  exposes only bounded counts, state enums, and digests. Exact reuse is
  zero-write; local `show` validates the record. The owner invokes no process,
  performs no mutation, collects no authorization, executes no postcheck,
  changes no journal, finalizes nothing, and adds no CLI/public wiring. Phase 4
  remains incomplete after this slice.
- **Implementation status — operation-bound storage postcheck and immutable
  reconciliation (26.9.19):** the internal
  `execute_deploy_storage_postcheck` owner accepts only canonical
  state-root/cluster identity, one operation UUID, the matching held deploy
  lock, a controlled runner, and the exact validated sibling Ansible
  executables/toolchain. It reloads the complete chain through immutable
  post-storage-prepare reconciliation and derives only its exact sorted current
  Scylla scopes, including preparation-success and explicitly non-mutated
  `owned-noop` provenance. The owner invokes only hash-checked
  `storage-postcheck`, serial one and check-mode enabled, after durably
  persisting `started`. Strict semantic parsing requires every device,
  RAID/XFS/UUID/fstab/mount/capacity/permission/marker and provenance check to
  pass; exit zero alone is insufficient. Any process or semantic uncertainty
  is manual-recovery-required and permanently no-retry.
  Owner-only
  `deploy-scylla-vms.ansible-deploy-storage-postcheck-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-storage-postcheck-evidence/v1` records live
  only under `<cluster-root>/operations/` and retain bounded status/capacity
  counts plus hashed device/provenance/blocker digests, never addresses,
  provider IDs, device paths, filesystem UUIDs, commands, variables, raw
  output, credentials, or secrets. Exact completed re-entry is zero-process.
  The subprocess-free `reconcile_deploy_storage_postcheck` owner persists
  immutable
  `deploy-scylla-vms.ansible-deploy-post-storage-postcheck-reconciliation/v1`,
  marks only complete current postcheck scopes evidence-bound succeeded, and
  makes only the immediate mutating `scylla-install` scopes
  `evidence-ready-authorization-required`. It neither infers health nor
  leapfrogs later gates. Local `show` recognizes all three records, while the
  common `IN_PROGRESS/VERIFY` journal remains byte-for-byte unchanged.
  The internal `authorize_deploy_scylla_install` owner revalidates that full
  chain, derives only the exact active Scylla stable-ID scope and catalog/source
  2026.2 package, repository, and authenticated signing-key provenance, and
  accepts ordinary interactive or `cli-yes` approval only. It persists
  immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-install-authorization/v1` under
  `<cluster-root>/operations/`; local `show` recognizes it, and authorization
  remains unconsumed until exact execution start.
  The follow-on internal `execute_deploy_scylla_install` owner reloads and
  recomputes the same complete chain plus current base-OS evidence and the exact
  controlled Ansible executable/toolchain binding. It derives only the
  immutable authorized serial-one stable-ID scopes and internally constructed
  Ubuntu 24.04/architecture/package/provenance variables. Generation-guarded
  owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-install-execution/v1` and
  immutable-prefix
  `deploy-scylla-vms.ansible-deploy-scylla-install-evidence/v1` records live
  only under `<cluster-root>/operations/`. Each attempt is durably `prepared`
  and then `started` before its sole controlled call; the first start consumes
  the whole authorization without rewriting it. Strict parsing requires exact
  package, repository, signing-key, source, command, target, and provenance
  identity, a masked/inactive service, and no configuration, storage, tuning,
  Manager, or service-start action. Exit zero alone is insufficient. Any
  started crash, timeout, interruption, malformed/unreachable/failed result,
  drift, or post-call persistence failure is manual-recovery-required and
  permanently no-retry/no-skip/no-continue/no-rollback. Exact completed
  re-entry is zero-process. The common `IN_PROGRESS/VERIFY` journal and prior
  artifacts remain byte-for-byte unchanged.
  The subprocess-free `reconcile_deploy_scylla_install` owner reloads that
  complete canonical chain and persists immutable owner-only
  `deploy-scylla-vms.ansible-deploy-post-scylla-install-reconciliation/v1`
  only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-post-scylla-install-reconciliation.json`.
  It requires exact terminal success and complete evidence for every authorized
  Scylla target: the bound 2026.2 package/repository/signing-key provenance,
  installed or current state, masked/inactive `scylla-server`, and no
  configuration, storage, tuning, Manager, or service-start action. Prepared,
  started, failed, uncertain, incomplete, duplicate, stale, or drifted state
  fails closed before persistence. Only exact `scylla-install` scopes become
  evidence-bound succeeded, and only immediate `scylla-configure` scopes may
  become `evidence-ready-authorization-required`; bootstrap, agents, health,
  and all later gates remain blocked or not performed. The redacted report
  retains only schemas, digests, and bounded counts. Exact re-entry is
  zero-write, local `show` recognizes the record, and the common journal and
  every prior artifact remain byte-for-byte unchanged. Configure
  execution, finalization, CLI, and public workflow wiring remain unavailable.
  The internal `authorize_deploy_scylla_configure` owner reloads and revalidates
  that full chain under the matching deploy lock. It derives only the exact
  mapping-position-twelve Scylla stable-ID scopes and value-free configuration
  intent from canonical desired state, observation, inventory, prior package
  evidence, catalog, and packaged source. The intent binds cluster/datacenter/
  rack and private identities, deterministic initial-stable-ID seed policy,
  exact 2026.2 package version, fixed data directories, wrapper template/role/
  playbook sources, rendered configuration, variables, command, and
  masked/inactive service policy through counts, enums, and digests. Caller
  scope and configuration values are forbidden. Only ordinary interactive or
  PLAN-permitted `cli-yes` proof is accepted; destructive proof is
  inapplicable and refused. Immutable owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-configure-authorization/v1` is
  persisted only at
  `<cluster-root>/operations/<operation-uuid>.ansible-deploy-scylla-configure-authorization.json`.
  Exact reuse is zero-write, authorization remains unconsumed, local `show`
  validates the record, and the common journal remains byte-for-byte at
  `IN_PROGRESS/VERIFY`. This owner invokes no process and cannot bypass
  topology, address, seed, install, storage, service, readiness, source, or
  drift gates. The internal `execute_deploy_scylla_configure` owner reloads and
  revalidates the same complete chain plus exact unconsumed authorization,
  derives only the authorized mapping-position-twelve target/configuration
  intents, and invokes only hash-checked `scylla-configure` one target at a
  time under the matching lock, controlled runner, and exact toolchain. It
  persists immutable-prefix owner-only
  `deploy-scylla-vms.ansible-deploy-scylla-configure-execution/v1` and
  `deploy-scylla-vms.ansible-deploy-scylla-configure-evidence/v1` below
  `<cluster-root>/operations/`. Each call is durably prepared and then started;
  the first started attempt consumes the whole authorization. Success requires
  strict proof of exact 2026.2, the exact two authorized root-owned `0644`
  configuration files and all authorized topology/seed/data/template/config
  digests, masked/inactive service, runtime validation not performed, and no
  install/storage/tuning/firewall/SSH/Manager/start/bootstrap action. Exit zero
  is insufficient. Any uncertainty after started is permanent manual recovery
  with no retry, skip, continuation, or rollback. Exact prepared prefixes may
  resume and exact completion is zero-process. Evidence and reports retain
  only stable IDs, bounded states/booleans/counts, schemas, and digests; local
  `show` validates both records. The journal and prior artifacts remain
  byte-for-byte at `IN_PROGRESS/VERIFY`. Post-configuration reconciliation,
  bootstrap, finalization, CLI, and public workflow wiring remain unavailable,
  so Phase 4 remains incomplete after this slice.
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

- Broader Manager, monitoring, and guest-OS version matrices. The selected
  initial baseline is exact Ubuntu 24.04 on `amd64`/`x86_64` and `aarch64` plus
  ScyllaDB release line 2026.2 with an exact package version. Python, Ansible,
  and Terraform CLI constraints are selected for implemented boundaries; the
  source constrains OCI provider `~>9.1.0`, while broader tested matrices and
  future provider-upgrade policy remain open.
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
- The v2 non-secret config decision is strict
  `deploy-scylla-vms.config/v2` TOML as documented above. v1 files and
  `deploy-scylla-vms.desired/v1` records are rejected rather than silently
  defaulting image or managed-network choices; future schema changes require an
  explicit version and migration decision.
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
- [OCI Ubuntu 24.04 platform images](https://docs.oracle.com/en-us/iaas/images/ubuntu-2404/index.htm)
- [OCI Bastion concepts](https://docs.oracle.com/en-us/iaas/Content/Bastion/Concepts/bastionoverview.htm)
- [OCI SDK and CLI configuration](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm)
- [OCI security best practices](https://docs.oracle.com/en-us/iaas/Content/Security/Reference/configuration_security.htm)

### ScyllaDB operations

- [ScyllaDB documentation](https://docs.scylladb.com/manual/stable/)
- [ScyllaDB 2026.2 Linux package installation](https://docs.scylladb.com/manual/branch-2026.2/getting-started/install-scylla/install-on-linux.html)
- [ScyllaDB OS support by version](https://docs.scylladb.com/stable/versioning/os-support-per-version.html)
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
