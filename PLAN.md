# Implementation Plan

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
  channels/versions.
- `ZoneSpec`: normalized zone ID, `scylla_rack`, and desired Scylla node count.
- `HostSpec`: stable logical ID, role, zone, ordinal, provider resource ID,
  private/public addresses, SSH route, lifecycle state, and nullable
  `scylla_datacenter`/`scylla_rack` fields that are required for Scylla hosts.
- `InstanceTypes`: separate Scylla, Manager, monitoring, and jump-host values.
- `TerraformOutputs`: versioned output schema containing only expected fields.
- `InventoryModel`: groups, hosts, connection routes, and non-secret variables.
- `OperationRecord`: operation ID, requested target, preconditions, completed
  phases, plan digest, timestamps, and non-secret outcomes.

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
cluster metadata, Terraform state, generated inventory, or operation journals.
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
jump-host routing references, `scylla_datacenter`, and `scylla_rack`. Both
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
   provider IDs associated with another logical host, missing topology fields on
   a Scylla node, non-null topology fields on a non-Scylla host, or a
   datacenter/rack value that differs from the persisted zone mapping;
5. build groups such as `scylla`, `manager`, `monitoring`, `jump_hosts`, and
   zone groups, plus Scylla datacenter/rack groups using inventory-safe derived
   group names;
6. generate `ansible_host`, `ansible_user`, ProxyJump-style connection metadata,
   and exact `scylla_datacenter`/`scylla_rack` hostvars without changing the
   logical label values or adding secrets;
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
an unresolved host-key change also blocks the operation. The tool must never
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
  kernel/sysctl/limits, disks/filesystems, and ScyllaDB hardware tuning;
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
policy.

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

1. Resolve configuration, validate the cluster name/topology, and acquire the
   new cluster's state lock; reject an existing cluster identity or unexpected
   Terraform state unless an interrupted deploy journal is safe to resume.
2. Validate environment-supplied credentials, OCI region/zones, node counts,
   explicit/defaulted Scylla datacenter and zone-to-rack mapping, shapes, quotas
   where queryable, storage, SSH route, and least-privilege network intent before
   creating resources.
3. Atomically create cluster metadata, stable cluster/host identities, desired
   topology including normalization algorithm/version and resolved
   datacenter/rack labels, and an operation journal; no Terraform apply occurs
   until those identifiers are durable.
4. Stage Terraform inputs in the canonical cluster root, then run
   init/validate and create a saved plan; display the role/zone/resource summary
   and require confirmation before apply.
5. Apply exactly the approved plan. On interruption or an uncertain provider
   result, stop at the infrastructure boundary, refresh Terraform state, and
   resume only after the plan/state lineage is reconciled.
6. Read fresh Terraform JSON outputs, generate and validate Ansible inventory,
   reject identity/address/zone/datacenter/rack conflicts, and establish SSH host
   trust and connectivity through the selected direct or bastion routes.
7. Run idempotent base and ScyllaDB playbooks in topology-safe order, limit
   initial bootstrap concurrency, and wait for all expected nodes to join and
   converge before continuing.
8. Configure the separate Manager and monitoring hosts, register the validated
   cluster, configure only explicitly requested repair/backup tasks, and
   generate monitoring targets from stable identities.
9. Validate ScyllaDB membership, datacenter/rack placement, ring health,
   services, Manager registration, monitoring targets, and a no-op convergence
   preview; stop rather than compensate destructively for partial configuration.
10. Atomically record final desired/observed topology, Terraform state/output
    and plan digests, inventory digest, health evidence, and completed phases.
    Preserve the journal for safe repair/resume if any postcondition failed.

### Add-node

1. Require exactly one new logical node identity and target zone, resolve its
   persisted cluster datacenter and zone rack, and reject an existing/tombstoned
   ID, undeclared/unmapped zone, or request that implicitly changes unrelated
   zone counts or existing topology labels.
2. Acquire the cluster lock and reconcile cluster metadata, Terraform state,
   fresh Terraform-output inventory, provider identities, and live ScyllaDB
   membership. Stop on drift, stale inventory, or an already-partially-added
   node unless its operation journal gives a valid resume boundary.
3. Verify ring health, failure-domain/replication policy, bootstrap capacity,
   keyspace replication across the resolved datacenter/racks, seed/address
   policy, Manager task posture, and supported ScyllaDB add-node procedure.
   Reserve the requested durable host ID without renumbering existing nodes.
4. Produce a saved Terraform plan for only the new host and necessary narrowly
   scoped dependencies; display provider ID/address expectations and require
   confirmation before applying infrastructure.
5. Apply the plan, refresh Terraform JSON output, regenerate/validate inventory,
   and establish host-key trust and the selected SSH/bastion path for the new
   host. Refuse any unrelated resource replacement.
6. Apply base and ScyllaDB roles only to the new node, then bootstrap it using
   the version-appropriate procedure. Do not add another node concurrently
   unless a future tested policy explicitly permits it.
7. Wait for token streaming/bootstrap completion and healthy membership; if
   configuration fails before join, repair or remove only the new infrastructure
   through a reviewed plan, but after ring mutation journal and resume rather
   than attempting an automatic rollback.
8. Refresh Manager and monitoring configuration, validate the new node's
   exact datacenter/rack, zone, ownership, service, and scrape/management status,
   then persist the desired count, observed membership/topology,
   inventory/output digests, and operation result.

### Scale-out

1. Accept a desired per-zone topology, acquire the cluster lock, and calculate
   the expansion from stable current identities; reject decreases (which belong
   to `scale-in`), implicit renumbering, unmapped zones, and any change to
   existing datacenter/rack labels.
2. Reconcile metadata, Terraform state, fresh Terraform-output inventory,
   provider resources, and live membership. Report the exact new IDs/zones and
   stop on drift or an incomplete prior scaling journal.
3. Validate the resulting odd/asymmetric topology, failure-domain/replication
   goals and keyspace replication across the resolved datacenter/racks, quotas,
   network/storage capacity, bootstrap load, and cluster health. Choose a
   deterministic, topology-safe node addition order.
4. Display a complete preview of the expansion and require confirmation for the
   full desired-topology delta. Partition execution into bounded batches or
   single nodes as required by bootstrap policy; after refreshing state, create
   a separate saved Terraform plan for each batch so no plan is partially
   applied.
5. For each approved node/batch, apply exactly its saved infrastructure plan,
   refresh Terraform output and inventory, validate SSH identity/routes, run
   base and ScyllaDB playbooks, and wait for streaming plus ring-health gates
   before planning the next addition.
6. On failure, stop before the next node, retain the achieved intermediate
   desired/observed distinction, and resume from the journal after
   reconciliation; never destroy a node that has joined the ring as an automatic
   Terraform rollback.
7. After all additions, regenerate Manager/monitoring targets once more and
   validate membership, token ownership, zone/rack distribution, services, and
   the requested final counts.
8. Record each completed node boundary, final topology, plan/state/output and
   inventory digests, and health evidence so the expansion is idempotent on
   rerun.

### Replace-node

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
   evidence.
4. Preserve the tool's stable logical node identity and record a replacement
   generation, exact datacenter/rack labels, and zone while assigning a new
   provider resource ID. A request to move zone/rack/datacenter is not a
   replacement and must be refused as an unsupported topology migration. Reuse
   an address only when explicitly planned and supported; otherwise pass the old
   identity or address to the version-appropriate Scylla replacement mechanism
   so token ownership transfers safely. Never manually duplicate tokens or treat
   this as an ordinary add.
5. Create a saved Terraform replacement plan showing destroyed/created compute,
   storage, addresses, and retained data; report backup implications and require
   target-ID plus cluster-ID confirmation before apply.
6. Apply the infrastructure plan, refresh outputs, regenerate/validate
   inventory, and require explicit approval of the new SSH host key after
   correlating it to the new provider instance.
7. Configure the replacement host and invoke the supported replacement
   bootstrap. Wait for streaming, token ownership, schema, and ring-health gates;
   do not run another topology operation concurrently.
8. Once replacement has entered the ring, automatic rollback is prohibited.
   Journal the last verified phase and resume after reconciliation; failed
   pre-join infrastructure may be replanned only if the old-node evidence and
   replacement generation remain intact.
9. Refresh Manager and monitoring, verify the old provider instance is absent or
   explicitly retained for forensics, validate the stable-ID-to-new-generation
   mapping and cluster health, and record before/after topology and digests.

### Destroy-node

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
   or failed-node removal procedure.
4. Present the exact node/provider IDs, data/storage disposition, resulting
   topology, and ordered Scylla-then-Terraform plan; require destructive
   confirmation before changing ring membership.
5. Disable or coordinate relevant Manager/monitoring activity, then decommission
   a live node or perform the supported dead-node removal. Wait until membership
   and token ownership prove the target is safely removed.
6. Treat successful ring removal as an irreversible resume boundary: record it
   before infrastructure deletion and never try to re-add the old VM
   automatically if later Terraform work fails.
7. Refresh Terraform state, create and confirm a saved plan that removes only
   the target VM/volumes/attachments and approved dependencies, apply it, then
   regenerate inventory from fresh outputs.
8. Tombstone the logical ID, refresh Manager/monitoring, validate surviving
   ring/services/topology and absence of the provider resource, and record
   membership evidence plus state/output/inventory digests.

### Scale-in

1. Accept lower desired per-zone counts, acquire the lock, and reject increases
   (which belong to `scale-out`) or mixed deltas that obscure the contraction.
2. Reconcile metadata, Terraform state, fresh Terraform-output inventory,
   provider resources, and live membership; calculate deterministic candidates
   by stable ID, never by list index or ephemeral address.
3. Validate the final odd/asymmetric topology, replication/failure-domain
   policy by datacenter/rack, keyspace replication, capacity, ring health,
   backup/repair posture, and Manager tasks. Refuse counts that would remove the
   last required role/zone/rack capacity.
4. Display every selected stable/provider ID, zone order, data/storage outcome,
   and final topology; allow explicit candidate override only after revalidation,
   then require confirmation for the complete contraction.
5. Process one node at a time by invoking the `destroy-node` safety sequence:
   decommission/remove in Scylla first, durably record that ring boundary, then
   apply the narrowly scoped Terraform deletion and refresh inventory.
6. Stop on any failed health or capacity gate. Preserve the safely achieved
   intermediate topology and resume from the next journaled candidate after
   reconciliation; never continue deleting to force the requested count.
7. After the final removal, refresh Manager and monitoring and validate surviving
   membership, token ownership, zone/rack distribution, services, and desired
   counts.
8. Persist tombstones, per-node completion evidence, final desired/observed
   topology, Terraform and inventory digests, and any partial-result status.

### Destroy

1. Require the full-cluster operation explicitly; reject node selectors and
   direct callers to `destroy-node`/`scale-in` for individual membership changes.
2. Acquire the exclusive cluster lock and reconcile metadata, Terraform state,
   fresh Terraform-output inventory, provider resources, and live membership.
   Refuse missing/ambiguous state, unmanaged members, or unresolved partial
   operations unless a separately designed recovery workflow resolves them.
3. Capture a protected pre-destroy diagnostic snapshot of topology, Terraform
   outputs, inventory, health, Manager tasks, monitoring targets, and resource
   IDs. Report independently verified backup status and all retained/external
   resources; never imply that Terraform destruction is a database backup.
4. Plan the application-level shutdown order and create a saved Terraform
   destroy plan. Display the validated cluster name and UUID, complete resource
   inventory, storage/data loss, network/shared-resource effects, and diagnostic
   retention policy.
5. Require strong confirmation that includes the exact cluster name and UUID;
   noninteractive approval also requires the dedicated destructive opt-in and
   cannot bypass identity, drift, backup-policy, or plan checks.
6. Quiesce/disable Manager tasks and monitoring writes as designed, then perform
   any required final ScyllaDB service shutdown. Do not individually decommission
   every node unless the supported full-cluster procedure specifically requires
   it.
7. Apply exactly the reviewed Terraform destroy plan. If interrupted or the
   provider outcome is uncertain, retain state and journal, refresh/reconcile,
   and produce a new destroy plan; do not delete state to make Terraform forget
   residual resources.
8. Verify through Terraform state and provider queries that all planned
   resources are gone and report approved retained/shared resources. Terraform
   outputs/inventory may no longer be available after destruction, so use the
   protected pre-destroy snapshot for diagnostics rather than regenerating a
   fictitious live inventory.
9. Mark the cluster destroyed and retain the converged Terraform state,
   sanitized diagnostics, tombstone, plan digest, and operation journal under
   the canonical cluster root. Remove only ephemeral credentials/generated
   connection data according to retention policy; never silently erase lifecycle
   evidence.

### Redeploy

1. Require an explicit scope and target: `service` for selected configuration/
   service convergence, `host` for one stable host, or `cluster` for
   cluster-wide reconciliation. Reject an unscoped request.
2. Acquire the lock and reconcile metadata, Terraform state, fresh
   Terraform-output inventory, provider identities, live membership, and the
   selected scope. Stop on topology/identity drift, including any existing
   datacenter/rack mismatch, instead of interpreting it as permission to
   recreate resources or relabel nodes.
3. Produce a scope-specific preview: Ansible-only service convergence,
   Terraform no-op/reconciliation plus Ansible for infrastructure configuration,
   or an explicitly identified host reprovision. By default, `redeploy` means
   reapply/reconcile, not destroy and recreate.
4. For service scope, validate capacity and dependencies, confirm any restart,
   run the smallest idempotent playbook/tag set, and health-check before moving
   to another service or host.
5. For host scope, permit ordinary reprovision only for stateless/approved
   roles. Reprovisioning a ScyllaDB node must delegate to `replace-node`; deleting
   it through a Terraform replacement plan is forbidden. Jump-host, Manager, and
   monitoring replacements require role-specific reachability/availability
   plans and confirmation.
6. For cluster scope, apply only a reviewed Terraform plan and bounded Ansible
   convergence that preserve cluster UUID, stable node IDs, and state. Any
   resource replacement is highlighted and separately confirmed.
7. Journal each host/service boundary. On failure, stop further convergence,
   preserve already healthy changes, and resume only after fresh reconciliation;
   rollback is limited to an explicitly tested configuration rollback, never an
   inferred infrastructure destroy.
8. Refresh outputs/inventory when infrastructure changed, then validate ring,
   services, SSH routes, Manager, and monitoring for the requested scope and
   record plan/config/inventory digests plus observed health.

### Refresh-monitoring

1. Acquire the cluster lock, read current Terraform state/output without an
   infrastructure apply, regenerate/validate inventory, and compare stable host
   identities with live ScyllaDB membership.
2. Stop on duplicate/stale identities, unexpected live members, unreachable
   monitoring hosts, or topology drift; monitoring refresh must not conceal a
   cluster/state conflict.
3. Derive a deterministic target/configuration diff for ScyllaDB, Manager, and
   monitoring components, preserving exact datacenter/rack labels, zones,
   endpoints, dashboards, alerts, retention, and non-secret operator settings.
4. Preview the generated targets and Ansible monitoring-only changes. Require
   confirmation for monitoring service restarts or destructive retention/data
   changes, but do not create a Terraform apply merely to rewrite targets.
5. Atomically write the external generated inventory/target inputs and run only
   the monitoring role/playbook against monitoring hosts; do not mutate
   ScyllaDB membership, packages, or unrelated cluster infrastructure.
6. Validate configuration syntax, service health, target discovery/scrape
   status, expected node/Manager coverage, and absence of stale targets. Restore
   the prior generated monitoring configuration only when that rollback is
   explicitly supported and validated.
7. Record inventory/output and target/config digests, monitoring health
   evidence, changes/restarts, and a resumable failure boundary; leave the
   Terraform state unchanged.

### Upgrade-os

1. Require an approved source/target OS and repository policy, explicit role/
   host scope, maintenance window, and evidence that the OS change is compatible
   with installed ScyllaDB, Manager, monitoring, Ansible, and OCI tooling. Do not
   combine a ScyllaDB major-version upgrade with this operation.
2. Acquire the lock and reconcile metadata, Terraform state, fresh
   Terraform-output inventory, provider image metadata, live membership, and any
   prior upgrade journal. Stop on drift or uncertain host generation.
3. Validate backups, ring/schema health, streaming/repair activity, free
   capacity, failure-domain tolerance, jump-host path redundancy, and
   Manager/monitoring availability. Refuse to begin if loss of one scoped host
   would violate policy.
4. Generate a per-host preflight/package/reboot plan and deterministic order.
   Call out that in-place package upgrade versus provider-image reprovision has
   different Terraform and data implications; until later design approves image
   reprovision, it is not an implicit part of `upgrade-os`, and Scylla host
   reprovision must use replacement semantics.
5. Display package removals, reboot needs, role order, capacity impact, and any
   Terraform image change; require confirmation before the first mutation and
   separate replacement confirmation if a future provider-image path is used.
6. Process exactly one host at a time. For a Scylla node, drain/coordinate only
   as required by version-specific guidance, apply the OS role, reboot if
   needed, restore service, and wait for membership, schema, token, and
   application health before continuing.
7. Upgrade jump hosts only while another validated route or an approved
   maintenance outage exists; upgrade Manager/monitoring hosts under their
   role-specific task, data, and observability safeguards.
8. Journal before patch, before reboot, and after health validation. On failure,
   stop the rollout; resume the same host after reconciliation. Package rollback
   or image rollback occurs only when explicitly supported/tested and must not
   create a second Scylla identity or stale address.
9. After all hosts, refresh Terraform output/inventory if provider attributes
   changed, rerun cluster/SSH/Manager/monitoring health checks, verify OS
   versions and no pending reboot, and record each host result plus final
   topology and digests.

### Check-jump-hosts

1. Run read-only by default, acquiring a shared/read cluster lock where
   supported (otherwise the normal lock), and reject flags that imply Terraform
   apply, host-key replacement, security-rule edits, or host mutation.
2. Reconcile cluster metadata with current Terraform state and fresh JSON
   outputs, derive and validate inventory in memory or a temporary protected
   file without replacing canonical inventory, and stop on jump-host identity,
   address, zone, or host-key conflicts.
3. Validate each configured direct or ProxyJump route: operator-to-bastion,
   bastion-to-assigned-private-host, deterministic multi-bastion selection, and
   zero-jump-host direct routing where applicable.
4. Correlate OCI provider IDs/addresses with the per-cluster known-hosts data,
   then test DNS/address resolution, SSH authentication, forwarding policy, and
   bounded noninteractive connectivity without disabling host-key checking.
5. Probe representative or all assigned ScyllaDB, Manager, and monitoring
   targets according to the requested depth; distinguish network/security-list,
   bastion SSH, target SSH, authentication, and host-key failures without
   exposing credentials.
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
  change.
- `--plan` creates Terraform plans and Ansible/check previews where safe, but
  does not apply.
- Mutating operations summarize cluster UUID, topology delta, resources, and
  health checks before confirmation.
- `--yes` is allowed for controlled automation only with an additional explicit
  destructive-operation opt-in; it cannot bypass drift, identity, or health
  gates.
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
inventory, provider identity, and live health, then determines whether a phase
is complete, safely repeatable, or requires intervention.

Classify topology drift:

- **expected/in-progress**: matches the active operation record;
- **benign configuration drift**: can be shown and reconciled by a reviewed plan;
- **identity or membership conflict**: blocks sensitive/destructive action; or
- **orphaned infrastructure/state**: requires explicit import/recovery workflow.

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
- versioned manifest serialization of required Scylla and null non-Scylla
  datacenter/rack fields;
- inventory schema validation, topology hostvar/group propagation, and
  datacenter/rack conflict/drift classification;
- confirmation and exit-code mapping;
- command construction with no shell interpolation; and
- operation journal resume decisions.

No unit test may contact real OCI, create VMs, run a real Terraform apply, or
change a real ScyllaDB cluster.

### Contract and integration tests

- Golden fixtures for supported Terraform JSON output versions, including
  datacenter/rack values, null role conventions, and schema-upgrade failures.
- Generated inventory checked by `ansible-inventory`, with exact topology
  hostvars and expected derived datacenter/rack groups.
- Terraform `fmt`, `validate`, and plan against mocked/test modules where
  practical.
- Ansible syntax checks, lint, check mode, and idempotence in disposable local
  containers/VMs.
- Fake process runner and provider adapters for failure, timeout, partial apply,
  stale lock, and interrupted operation scenarios.
- Optional explicitly gated OCI sandbox tests with isolated compartments,
  budgets/quotas, unique tags, teardown verification, and no production
  credentials.

### End-to-end scenarios

In an approved ephemeral environment: deploy; no-op rerun; scale out; refresh
monitoring; replace a failed node; scale in; rolling OS upgrade; interruption and
resume; drift refusal; and full destroy. Capture topology and health evidence at
each stage.

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
  datacenter/rack mappings, and configuration precedence.

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
  resolved datacenter/rack schema and validate.

### Phase 3 — inventory and baseline Ansible

- Implement deterministic transformation, SSH trust/routing, base role, ScyllaDB,
  separate Manager, and monitoring playbooks.
- Acceptance: zero/one/multiple jump-host inventories validate; repeat Ansible
  run is idempotent; exact datacenter/rack hostvars reach Scylla configuration
  and are verified from Scylla; relabel drift is refused; no secret enters
  inventory or logs.

### Phase 4 — deploy and reconciliation

- Complete deploy, dry-run/plan/apply gates, postconditions, and resume.
- Acceptance: ephemeral cluster deploys, converges on rerun, survives a
  controlled interruption, and reports injected drift before mutation.

### Phase 5 — node lifecycle and scaling

- Add add/replace/destroy node and scale workflows.
- Acceptance: stable identities never renumber; uneven topology behaves as
  declared; add/scale preserve zone-to-rack mappings, replacement preserves the
  target's datacenter/rack, and each workflow gates on replication/topology
  health and updates Manager/monitoring.

### Phase 6 — maintenance and destruction

- Add redeploy, refresh-monitoring, upgrade-os, check-jump-hosts, and full
  destroy.
- Acceptance: rolling operations stop on failed health gates; destroy refuses
  conflict and removes only reviewed resources; tombstone remains.

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
- Storage layout and data durability policy per ScyllaDB-supported instance
  shape.
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

### Ansible

- [Ansible inventory guide](https://docs.ansible.com/ansible/latest/inventory_guide/index.html)
- [Working with inventory](https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html)
- [Inventory plugins](https://docs.ansible.com/ansible/latest/plugins/inventory.html)
- [Developing inventory plugins](https://docs.ansible.com/ansible/latest/dev_guide/developing_inventory.html)
- [Ansible security guidance](https://docs.ansible.com/ansible/latest/reference_appendices/security.html)

### OCI

- [OCI documentation](https://docs.oracle.com/en-us/iaas/Content/home.htm)
- [OCI networking](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/overview.htm)
- [OCI network security groups](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/networksecuritygroups.htm)
- [OCI Compute instance metadata](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm)
- [OCI SDK and CLI configuration](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm)
- [OCI security best practices](https://docs.oracle.com/en-us/iaas/Content/Security/Reference/configuration_security.htm)

### ScyllaDB operations

- [ScyllaDB documentation](https://docs.scylladb.com/manual/stable/)
- [ScyllaDB cluster management](https://docs.scylladb.com/manual/stable/operating-scylla/)
- [ScyllaDB Manager documentation](https://manager.docs.scylladb.com/stable/)
- [ScyllaDB Monitoring documentation](https://monitoring.docs.scylladb.com/stable/)
- [ScyllaDB upgrade documentation](https://docs.scylladb.com/manual/stable/upgrade/)

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
