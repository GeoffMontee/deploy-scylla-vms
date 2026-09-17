locals {
  private_jump_ids = sort(keys(local.jump_hosts))

  host_subnet_ids = {
    for logical_id, host in local.hosts_by_id : logical_id => (
      local.managed_network
      ? (
        host.role == "jump-host" && host.assign_public_ip
        ? local.managed_public_subnet_ids[host.zone]
        : local.managed_private_subnet_ids[host.zone]
      )
      : host.subnet_id
    )
  }

  host_jump_ids = {
    for logical_id, host in local.hosts_by_id : logical_id => (
      host.role == "jump-host" || length(local.private_jump_ids) == 0
      ? null
      : local.private_jump_ids[
        parseint(substr(sha256(logical_id), 0, 8), 16) % length(local.private_jump_ids)
      ]
    )
  }
}

resource "oci_core_instance" "host" {
  for_each = local.hosts_by_id

  availability_domain  = each.value.zone
  compartment_id       = var.deploy_scylla_vms_input.compartment_id
  display_name         = "${var.deploy_scylla_vms_input.cluster_name}-${each.key}"
  shape                = each.value.shape
  freeform_tags        = each.value.freeform_tags
  preserve_boot_volume = false

  create_vnic_details {
    assign_public_ip       = each.value.assign_public_ip
    display_name           = "${var.deploy_scylla_vms_input.cluster_name}-${each.key}"
    hostname_label         = substr("h${substr(sha256(each.key), 0, 14)}", 0, 15)
    nsg_ids                = [oci_core_network_security_group.role[each.value.role].id]
    skip_source_dest_check = false
    subnet_id              = local.host_subnet_ids[each.key]
  }

  metadata = {
    ssh_authorized_keys = var.deploy_scylla_vms_input.public_ssh_key
  }

  source_details {
    source_id   = each.value.image_id
    source_type = "image"
  }

  lifecycle {
    precondition {
      condition = (
        local.selected_images["${each.value.role}|${each.value.shape}"].id ==
        each.value.image_id
      )
      error_message = "The instance image must match the reviewed image-selection evidence."
    }

    precondition {
      condition     = !each.value.assign_public_ip || each.value.role == "jump-host"
      error_message = "Only jump hosts may request a public VNIC."
    }
  }
}
