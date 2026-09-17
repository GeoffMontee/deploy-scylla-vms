locals {
  active_roles = toset([for host in var.deploy_scylla_vms_input.hosts : host.role])
  private_roles = toset([
    for role in local.active_roles : role
    if role != "jump-host"
  ])
  has_jump_hosts = contains(local.active_roles, "jump-host")
}

resource "oci_core_network_security_group" "role" {
  for_each = local.active_roles

  compartment_id = var.deploy_scylla_vms_input.compartment_id
  vcn_id         = local.selected_vcn_id
  display_name   = "${local.network_name_prefix}-${replace(each.key, "-", "")}-nsg"
  freeform_tags = merge(local.network_tags, {
    "deploy-scylla-vms.component" = "network-security-group"
    "deploy-scylla-vms.role"      = each.key
  })
}

resource "oci_core_network_security_group_security_rule" "egress" {
  for_each = local.active_roles

  network_security_group_id = oci_core_network_security_group.role[each.key].id
  direction                 = "EGRESS"
  protocol                  = "all"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  stateless                 = false
  description               = "Stateful outbound access required for package installation and service operation."
}

resource "oci_core_network_security_group_security_rule" "operator_to_jump_ssh" {
  for_each = local.has_jump_hosts ? toset(var.deploy_scylla_vms_input.network.operator_cidrs) : toset([])

  network_security_group_id = oci_core_network_security_group.role["jump-host"].id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = each.value
  source_type               = "CIDR_BLOCK"
  stateless                 = false
  description               = "Operator SSH to jump hosts only."

  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

resource "oci_core_network_security_group_security_rule" "jump_to_private_ssh" {
  for_each = local.has_jump_hosts ? local.private_roles : toset([])

  network_security_group_id = oci_core_network_security_group.role[each.key].id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = oci_core_network_security_group.role["jump-host"].id
  source_type               = "NETWORK_SECURITY_GROUP"
  stateless                 = false
  description               = "SSH from the cluster jump-host security group."

  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

resource "oci_core_network_security_group_security_rule" "scylla_internode" {
  for_each = contains(local.active_roles, "scylla") ? {
    internode     = 7000
    internode_tls = 7001
  } : {}

  network_security_group_id = oci_core_network_security_group.role["scylla"].id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = oci_core_network_security_group.role["scylla"].id
  source_type               = "NETWORK_SECURITY_GROUP"
  stateless                 = false
  description               = "Scylla internode ${each.key} traffic."

  tcp_options {
    destination_port_range {
      min = each.value
      max = each.value
    }
  }
}

resource "oci_core_network_security_group_security_rule" "manager_to_scylla" {
  for_each = contains(local.active_roles, "manager") && contains(local.active_roles, "scylla") ? {
    agent = 10001
    cql   = 9042
  } : {}

  network_security_group_id = oci_core_network_security_group.role["scylla"].id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = oci_core_network_security_group.role["manager"].id
  source_type               = "NETWORK_SECURITY_GROUP"
  stateless                 = false
  description               = "Manager server to Scylla ${each.key} endpoint."

  tcp_options {
    destination_port_range {
      min = each.value
      max = each.value
    }
  }
}

resource "oci_core_network_security_group_security_rule" "monitoring_to_scylla" {
  for_each = contains(local.active_roles, "monitoring") && contains(local.active_roles, "scylla") ? {
    node_exporter = 9100
    prometheus    = 9180
  } : {}

  network_security_group_id = oci_core_network_security_group.role["scylla"].id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = oci_core_network_security_group.role["monitoring"].id
  source_type               = "NETWORK_SECURITY_GROUP"
  stateless                 = false
  description               = "Monitoring host to Scylla ${each.key} endpoint."

  tcp_options {
    destination_port_range {
      min = each.value
      max = each.value
    }
  }
}

check "ssh_ingress_relationships" {
  assert {
    condition = (
      local.has_jump_hosts
      ? length(var.deploy_scylla_vms_input.network.operator_cidrs) > 0
      : length(var.deploy_scylla_vms_input.network.operator_cidrs) == 0
    )
    error_message = "Operator SSH CIDRs require jump hosts, and jump hosts require explicit operator CIDRs."
  }
}
