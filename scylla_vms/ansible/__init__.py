"""Controlled Ansible execution, catalog, source, and SSH trust contracts."""

from scylla_vms.ansible.registry import PLAYBOOKS, get_playbook

__all__ = ["PLAYBOOKS", "get_playbook"]
