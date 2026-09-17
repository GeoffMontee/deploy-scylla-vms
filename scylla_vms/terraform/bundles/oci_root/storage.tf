locals {
  block_volume_specs = {
    for item in flatten([
      for logical_id, host in local.hosts_by_id : [
        for index in range(
          host.storage.selected_backend == "block-volume"
          ? host.storage.block_volume.count
          : 0
          ) : {
          key        = format("%s:%04d", logical_id, index + 1)
          logical_id = logical_id
          index      = index + 1
          host       = host
        }
      ]
    ]) : item.key => item
  }

  retained_block_volume_specs = {
    for key, item in local.block_volume_specs : key => item
    if item.host.storage.block_volume.retention == "retain"
  }
  deleted_block_volume_specs = {
    for key, item in local.block_volume_specs : key => item
    if item.host.storage.block_volume.retention == "delete"
  }

  storage_tags = {
    for key, item in local.block_volume_specs : key => merge(
      item.host.freeform_tags,
      {
        "deploy-scylla-vms.component"    = "data-volume"
        "deploy-scylla-vms.device-index" = tostring(item.index)
        "deploy-scylla-vms.retention"    = item.host.storage.block_volume.retention
      }
    )
  }
}

resource "oci_core_volume" "retained" {
  for_each = local.retained_block_volume_specs

  availability_domain = each.value.host.zone
  compartment_id      = var.deploy_scylla_vms_input.compartment_id
  display_name        = "${var.deploy_scylla_vms_input.cluster_name}-${each.value.logical_id}-data-${format("%02d", each.value.index)}"
  freeform_tags       = local.storage_tags[each.key]
  kms_key_id          = each.value.host.storage.block_volume.key_id
  size_in_gbs         = each.value.host.storage.block_volume.size_gib
  vpus_per_gb         = each.value.host.storage.block_volume.vpus_per_gb

  lifecycle {
    prevent_destroy = true
  }
}

resource "oci_core_volume" "deleted" {
  for_each = local.deleted_block_volume_specs

  availability_domain = each.value.host.zone
  compartment_id      = var.deploy_scylla_vms_input.compartment_id
  display_name        = "${var.deploy_scylla_vms_input.cluster_name}-${each.value.logical_id}-data-${format("%02d", each.value.index)}"
  freeform_tags       = local.storage_tags[each.key]
  kms_key_id          = each.value.host.storage.block_volume.key_id
  size_in_gbs         = each.value.host.storage.block_volume.size_gib
  vpus_per_gb         = each.value.host.storage.block_volume.vpus_per_gb
}

locals {
  block_volume_ids = merge(
    { for key, volume in oci_core_volume.retained : key => volume.id },
    { for key, volume in oci_core_volume.deleted : key => volume.id },
  )
}

resource "oci_core_volume_attachment" "data" {
  for_each = local.block_volume_specs

  attachment_type                     = each.value.host.storage.block_volume.attachment_type
  instance_id                         = oci_core_instance.host[each.value.logical_id].id
  volume_id                           = local.block_volume_ids[each.key]
  is_pv_encryption_in_transit_enabled = each.value.host.storage.block_volume.in_transit_encryption
  is_read_only                        = false
  is_shareable                        = false
  use_chap                            = false

  lifecycle {
    precondition {
      condition     = each.value.host.storage.block_volume.chap_enabled == false
      error_message = "CHAP attachments are unsupported by the approved credential boundary."
    }
  }
}

check "local_nvme_capability_contract" {
  assert {
    condition = alltrue([
      for host in values(local.hosts_by_id) :
      host.storage.selected_backend != "local-nvme" ||
      (
        host.role == "scylla" &&
        host.storage.provider_local_device_count >= host.storage.local_min_device_count &&
        host.storage.provider_local_total_gib >= host.storage.local_min_total_gib &&
        host.storage.block_volume == null
      )
    ])
    error_message = "Local-NVMe selection must remain bound to adequate provider capability facts."
  }
}

check "block_volume_policy_contract" {
  assert {
    condition = alltrue([
      for host in values(local.hosts_by_id) :
      host.storage.selected_backend != "block-volume" ||
      (
        host.storage.block_volume != null &&
        host.storage.block_volume.count > 0 &&
        host.storage.block_volume.size_gib > 0 &&
        host.storage.block_volume.vpus_per_gb >= 0 &&
        contains(["iscsi", "paravirtualized"], host.storage.block_volume.attachment_type) &&
        contains(["delete", "retain"], host.storage.block_volume.retention) &&
        host.storage.block_volume.chap_enabled == false
      )
    ])
    error_message = "Block Volume selection requires a complete supported volume and attachment policy."
  }
}
