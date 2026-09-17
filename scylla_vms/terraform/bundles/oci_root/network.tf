locals {
  managed_network = var.deploy_scylla_vms_input.network.mode == "create"
  jump_hosts = {
    for logical_id, host in local.hosts_by_id : logical_id => host
    if host.role == "jump-host"
  }
  jump_zones        = toset([for host in values(local.jump_hosts) : host.zone])
  public_jump_zones = var.deploy_scylla_vms_input.network.allow_public_jump_hosts ? local.jump_zones : toset([])

  managed_private_subnets = local.managed_network ? var.deploy_scylla_vms_input.network.private_subnet_cidrs : {}
  managed_public_subnets  = local.managed_network ? var.deploy_scylla_vms_input.network.public_subnet_cidrs : {}

  network_tags = {
    "deploy-scylla-vms.cluster-name" = var.deploy_scylla_vms_input.cluster_name
    "deploy-scylla-vms.cluster-uuid" = var.deploy_scylla_vms_input.cluster_uuid
    "deploy-scylla-vms.managed-by"   = "deploy-scylla-vms"
  }
  network_name_prefix = "${var.deploy_scylla_vms_input.cluster_name}-${substr(md5(var.deploy_scylla_vms_input.cluster_uuid), 0, 8)}"
}

resource "oci_core_vcn" "managed" {
  count = local.managed_network ? 1 : 0

  compartment_id = var.deploy_scylla_vms_input.compartment_id
  cidr_block     = var.deploy_scylla_vms_input.network.vcn_cidr
  display_name   = "${local.network_name_prefix}-vcn"
  dns_label      = "dsv${substr(md5(var.deploy_scylla_vms_input.cluster_uuid), 0, 12)}"
  is_ipv6enabled = false
  freeform_tags  = merge(local.network_tags, { "deploy-scylla-vms.component" = "vcn" })
}

locals {
  selected_vcn_id = local.managed_network ? oci_core_vcn.managed[0].id : var.deploy_scylla_vms_input.network.vcn_id
}

resource "oci_core_internet_gateway" "jump" {
  count = local.managed_network && length(local.managed_public_subnets) > 0 ? 1 : 0

  compartment_id = var.deploy_scylla_vms_input.compartment_id
  vcn_id         = local.selected_vcn_id
  enabled        = true
  display_name   = "${local.network_name_prefix}-jump-internet"
  freeform_tags  = merge(local.network_tags, { "deploy-scylla-vms.component" = "internet-gateway" })
}

resource "oci_core_nat_gateway" "private" {
  count = local.managed_network ? 1 : 0

  compartment_id = var.deploy_scylla_vms_input.compartment_id
  vcn_id         = local.selected_vcn_id
  block_traffic  = false
  display_name   = "${local.network_name_prefix}-private-nat"
  freeform_tags  = merge(local.network_tags, { "deploy-scylla-vms.component" = "nat-gateway" })
}

resource "oci_core_route_table" "private" {
  count = local.managed_network ? 1 : 0

  compartment_id = var.deploy_scylla_vms_input.compartment_id
  vcn_id         = local.selected_vcn_id
  display_name   = "${local.network_name_prefix}-private-egress"
  freeform_tags  = merge(local.network_tags, { "deploy-scylla-vms.component" = "private-route-table" })

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_nat_gateway.private[0].id
    description       = "Private outbound access through the managed NAT gateway."
  }
}

resource "oci_core_route_table" "public" {
  count = local.managed_network && length(local.managed_public_subnets) > 0 ? 1 : 0

  compartment_id = var.deploy_scylla_vms_input.compartment_id
  vcn_id         = local.selected_vcn_id
  display_name   = "${local.network_name_prefix}-jump-public"
  freeform_tags  = merge(local.network_tags, { "deploy-scylla-vms.component" = "public-route-table" })

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.jump[0].id
    description       = "Public jump-host subnet route through the managed internet gateway."
  }
}

resource "oci_core_subnet" "private" {
  for_each = local.managed_private_subnets

  compartment_id             = var.deploy_scylla_vms_input.compartment_id
  vcn_id                     = local.selected_vcn_id
  cidr_block                 = each.value
  display_name               = "${local.network_name_prefix}-private-${substr(md5(each.key), 0, 8)}"
  dns_label                  = "p${substr(md5("${var.deploy_scylla_vms_input.cluster_uuid}:private:${each.key}"), 0, 14)}"
  prohibit_internet_ingress  = true
  prohibit_public_ip_on_vnic = true
  route_table_id             = oci_core_route_table.private[0].id
  security_list_ids          = []
  freeform_tags = merge(local.network_tags, {
    "deploy-scylla-vms.component" = "private-subnet"
    "deploy-scylla-vms.zone"      = each.key
  })
}

resource "oci_core_subnet" "public_jump" {
  for_each = local.managed_public_subnets

  compartment_id             = var.deploy_scylla_vms_input.compartment_id
  vcn_id                     = local.selected_vcn_id
  cidr_block                 = each.value
  display_name               = "${local.network_name_prefix}-jump-${substr(md5(each.key), 0, 8)}"
  dns_label                  = "j${substr(md5("${var.deploy_scylla_vms_input.cluster_uuid}:public:${each.key}"), 0, 14)}"
  prohibit_internet_ingress  = false
  prohibit_public_ip_on_vnic = false
  route_table_id             = oci_core_route_table.public[0].id
  security_list_ids          = []
  freeform_tags = merge(local.network_tags, {
    "deploy-scylla-vms.component" = "jump-subnet"
    "deploy-scylla-vms.zone"      = each.key
  })
}

locals {
  managed_private_subnet_ids = {
    for zone, subnet in oci_core_subnet.private : zone => subnet.id
  }
  managed_public_subnet_ids = {
    for zone, subnet in oci_core_subnet.public_jump : zone => subnet.id
  }
}

check "managed_subnet_zone_contract" {
  assert {
    condition = (
      !local.managed_network ||
      (
        length(setsubtract(toset(keys(local.managed_private_subnets)), toset([for host in var.deploy_scylla_vms_input.hosts : host.zone]))) == 0 &&
        length(setsubtract(toset([for host in var.deploy_scylla_vms_input.hosts : host.zone]), toset(keys(local.managed_private_subnets)))) == 0 &&
        length(setsubtract(toset(keys(local.managed_public_subnets)), local.public_jump_zones)) == 0 &&
        length(setsubtract(local.public_jump_zones, toset(keys(local.managed_public_subnets)))) == 0
      )
    )
    error_message = "Managed subnet zones must exactly cover private hosts and public jump-host placement."
  }
}

check "existing_network_ownership" {
  assert {
    condition = (
      local.managed_network ||
      (
        length(local.managed_private_subnets) == 0 &&
        length(local.managed_public_subnets) == 0 &&
        var.deploy_scylla_vms_input.network.vcn_id != null
      )
    )
    error_message = "Existing mode must not declare managed network ownership."
  }
}

check "host_subnet_selection" {
  assert {
    condition = (
      local.managed_network
      ? alltrue([
        for host in var.deploy_scylla_vms_input.hosts :
        host.subnet_id == null &&
        host.subnet_key == (
          host.role == "jump-host" && host.assign_public_ip
          ? "public:${host.zone}"
          : "private:${host.zone}"
        ) &&
        (
          host.role == "jump-host" && host.assign_public_ip
          ? contains(keys(local.managed_public_subnets), host.zone)
          : contains(keys(local.managed_private_subnets), host.zone)
        )
      ])
      : (
        length(setsubtract(local.active_roles, toset(keys(var.deploy_scylla_vms_input.network.subnet_ids)))) == 0 &&
        length(setsubtract(toset(keys(var.deploy_scylla_vms_input.network.subnet_ids)), local.active_roles)) == 0 &&
        alltrue([
          for host in var.deploy_scylla_vms_input.hosts :
          host.subnet_key == null &&
          host.subnet_id == var.deploy_scylla_vms_input.network.subnet_ids[host.role]
        ])
      )
    )
    error_message = "Host subnet selection conflicts with the managed or existing network contract."
  }
}
