# deploy-scylla-vms

`deploy-scylla-vms` is a planned Python command-line tool for provisioning and
operating ScyllaDB clusters on virtual machines.

**Current status:** planning and documentation scaffold only. The proposed
`deploy_scylla_vms.py` script, Python package, Terraform modules, Ansible
playbooks, and tests do not exist yet. Nothing in this repository currently
creates, changes, or destroys infrastructure.

Version: `26.9.1`

## Table of contents

- [Intended capabilities](#intended-capabilities)
- [Planned stack](#planned-stack)
- [Configuration and safety principles](#configuration-and-safety-principles)
- [Planned usage — not functional](#planned-usage--not-functional)
- [Repository contents](#repository-contents)
- [Limitations](#limitations)
- [Documentation to consult during implementation](#documentation-to-consult-during-implementation)

## Intended capabilities

The design in `PLAN.md` covers:

- an extensible operation model with `deploy`, `add-node`, `replace-node`,
  `destroy-node`, `destroy`, `scale-out`, `scale-in`, `redeploy`,
  `refresh-monitoring`, `upgrade-os`, and `check-jump-hosts`;
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

- Python standard-library CLI/process/logging facilities plus
  [`platformdirs`](https://platformdirs.readthedocs.io/) for the canonical
  per-user state root, with typed validated models and other packaging choices
  to be finalized.
- [Terraform](https://developer.hashicorp.com/terraform) and the
  [OCI provider](https://registry.terraform.io/providers/oracle/oci/latest/docs)
  for infrastructure.
- [Ansible](https://docs.ansible.com/) for host configuration and orchestration.
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
- Terraform state is sensitive and must be protected with restrictive access,
  locking, encryption/versioning where available, and explicit backend policy.
- Generated Ansible inventory will be refreshed from validated Terraform JSON
  output before sensitive or destructive actions. Identity, topology,
  membership, and host-key conflicts will stop the operation.
- Private cluster hosts will not be exposed publicly by default. Zero-jump-host
  deployments require another verified private route; jump-host deployments
  require deterministic SSH routing and host-key verification.
- Destructive and rolling operations will require current reconciliation,
  health gates, exact stable target IDs, backup-policy reporting where
  applicable, and explicit confirmation.

These are design commitments, not currently executable protections.

`.gitignore` does not configure Terraform state placement. Its broad
`.terraform/`, `*.tfstate`, plan, and crash patterns are defense-in-depth against
accidental generated files anywhere in the checkout. `.terraform/` is
Terraform's provider/module/backend working cache, not the state directory.
`.terraform.lock.hcl` remains trackable for reproducible provider selections.

## Planned usage — not functional

The eventual CLI is expected to resemble:

```console
$ python deploy_scylla_vms.py deploy \
    --cloud-provider oci \
    --cluster-name example \
    --state-dir /operator-selected/per-user-state-root \
    --zone AD-1 \
    --zone AD-2 \
    --nodes-per-zone AD-1=3 \
    --nodes-per-zone AD-2=3 \
    --jump-host-count 1 \
    --plan
```

This example is illustrative only. There is no executable script or
infrastructure implementation in the repository yet, and argument names may
change during implementation review.

## Repository contents

- `PLAN.md` — comprehensive implementation plan, operation workflows,
  architecture, safety model, testing strategy, milestones, and references.
- `AGENTS.md` — coding, test, documentation, infrastructure, Ansible, security,
  versioning, and contribution rules for future agents.
- `.gitignore` — defense-in-depth exclusions for accidental Python, Terraform,
  Ansible, secret, test, editor, and OS runtime artifacts; it does not select the
  application state location.
- `LICENSE` — MIT License.
- `README.md` — current project overview and status.
- `VERSION` — current project version.
- `RELEASE_NOTES.md` — release-level documentation history.

## Limitations

- No CLI, provider adapter, Terraform, Ansible, test, packaging, or CI code has
  been implemented.
- No supported Python, Terraform, OCI provider, Ansible, ScyllaDB, Manager,
  monitoring, or guest OS version matrix has been selected.
- Network architecture, OCI auth methods, storage profiles, replication policy,
  backup policy, Terraform backend, and distribution model require explicit
  decisions listed in `PLAN.md`.
- AWS and GCP are architectural extension points only, not supported providers.
- No real infrastructure validation has been performed.

## Documentation to consult during implementation

Project-specific sources:

- [OCI provider for Terraform](https://registry.terraform.io/providers/oracle/oci/latest/docs)
- [ScyllaDB Ansible integration](https://docs.scylladb.com/manual/stable/using-scylla/integrations/integration-ansible.html)
- [ScyllaDB Ansible roles](https://github.com/scylladb/scylla-ansible-roles)
- [ScyllaDB Ansible roles wiki](https://github.com/scylladb/scylla-ansible-roles/wiki)

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
