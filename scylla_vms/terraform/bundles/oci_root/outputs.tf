output "schema_version" {
  description = "Version of the complete strict Terraform output contract."
  value       = "deploy-scylla-vms.terraform-output/v1"
}

output "image_selection" {
  description = "Strict deterministic selected-image evidence."
  value = {
    schema_version = "deploy-scylla-vms.terraform-image-selection/v1"
    cluster_uuid   = var.deploy_scylla_vms_input.cluster_uuid
    cluster_name   = var.deploy_scylla_vms_input.cluster_name
    provider       = var.deploy_scylla_vms_input.provider
    images = tolist([
      for logical_id in sort(keys(local.hosts_by_id)) : {
        logical_id         = logical_id
        image_id           = try(local.selected_images["${local.hosts_by_id[logical_id].role}|${local.hosts_by_id[logical_id].shape}"].id, null)
        image_name         = try(local.selected_images["${local.hosts_by_id[logical_id].role}|${local.hosts_by_id[logical_id].shape}"].display_name, null)
        image_time_created = try(local.selected_images["${local.hosts_by_id[logical_id].role}|${local.hosts_by_id[logical_id].shape}"].time_created, null)
        role               = local.hosts_by_id[logical_id].role
        shape              = local.hosts_by_id[logical_id].shape
        filter = {
          operating_system         = var.deploy_scylla_vms_input.image_filters[local.hosts_by_id[logical_id].role].operating_system
          operating_system_version = var.deploy_scylla_vms_input.image_filters[local.hosts_by_id[logical_id].role].operating_system_version
          version_match            = var.deploy_scylla_vms_input.image_filters[local.hosts_by_id[logical_id].role].version_match
        }
      }
    ])
  }
}

output "network_evidence" {
  description = "Strict non-sensitive network ownership and selection evidence."
  value = {
    schema_version             = "deploy-scylla-vms.terraform-network-evidence/v1"
    cluster_uuid               = var.deploy_scylla_vms_input.cluster_uuid
    cluster_name               = var.deploy_scylla_vms_input.cluster_name
    provider                   = var.deploy_scylla_vms_input.provider
    mode                       = var.deploy_scylla_vms_input.network.mode
    vcn_id                     = local.selected_vcn_id
    external_routing_validated = false
    ownership = {
      vcn          = local.managed_network
      gateways     = local.managed_network
      route_tables = local.managed_network
      subnets      = local.managed_network
    }
    subnets = tolist(
      local.managed_network ? [
        for key in sort(concat(
          [for zone in keys(local.managed_private_subnet_ids) : "${zone}|private"],
          [for zone in keys(local.managed_public_subnet_ids) : "${zone}|jump-host"],
          )) : {
          zone      = split("|", key)[0]
          role      = split("|", key)[1]
          access    = split("|", key)[1] == "jump-host" ? "public" : "private"
          subnet_id = split("|", key)[1] == "jump-host" ? local.managed_public_subnet_ids[split("|", key)[0]] : local.managed_private_subnet_ids[split("|", key)[0]]
          owned     = true
        }
        ] : [
        for key in sort(distinct([
          for host in var.deploy_scylla_vms_input.hosts : "${host.zone}|${host.role}"
          ])) : {
          zone      = split("|", key)[0]
          role      = split("|", key)[1]
          access    = split("|", key)[1] == "jump-host" && var.deploy_scylla_vms_input.network.allow_public_jump_hosts ? "public" : "private"
          subnet_id = var.deploy_scylla_vms_input.network.subnet_ids[split("|", key)[1]]
          owned     = false
        }
      ]
    )
    network_security_groups = tolist([
      for role in sort(keys(oci_core_network_security_group.role)) : {
        role = role
        id   = oci_core_network_security_group.role[role].id
      }
    ])
  }
}

locals {
  local_storage_devices = {
    for logical_id, host in local.hosts_by_id : logical_id => [
      for index in range(
        host.storage.selected_backend == "local-nvme"
        ? host.storage.provider_local_device_count
        : 0
        ) : {
        at_rest_encryption     = "provider-managed"
        attachment_type        = null
        customer_key_id        = null
        ephemeral              = true
        expected_by_id         = null
        expected_serial        = null
        expected_wwn           = null
        in_transit_encryption  = false
        iqn                    = null
        kind                   = "local-nvme"
        local_device_id        = null
        multipath_id           = null
        portal                 = null
        provider_attachment_id = null
        provider_volume_id     = null
        requested_path         = null
        retention              = null
        size_gib               = floor(host.storage.provider_local_total_gib / host.storage.provider_local_device_count) + (index < host.storage.provider_local_total_gib % host.storage.provider_local_device_count ? 1 : 0)
        vpus_per_gb            = null
      }
    ]
  }

  block_storage_devices = {
    for logical_id, host in local.hosts_by_id : logical_id => [
      for volume_id in sort([
        for key, item in local.block_volume_specs : local.block_volume_ids[key]
        if item.logical_id == logical_id
        ]) : {
        at_rest_encryption    = host.storage.block_volume.key_id == null ? "provider-managed" : "customer-managed"
        attachment_type       = host.storage.block_volume.attachment_type
        customer_key_id       = host.storage.block_volume.key_id
        ephemeral             = false
        expected_by_id        = null
        expected_serial       = null
        expected_wwn          = null
        in_transit_encryption = host.storage.block_volume.in_transit_encryption
        iqn = try(
          oci_core_volume_attachment.data[
            one([for key, item in local.block_volume_specs : key if local.block_volume_ids[key] == volume_id])
          ].iqn,
          null,
        )
        kind            = "block-volume"
        local_device_id = null
        multipath_id    = null
        portal = try(
          format(
            "%s:%d",
            oci_core_volume_attachment.data[
              one([for key, item in local.block_volume_specs : key if local.block_volume_ids[key] == volume_id])
            ].ipv4,
            oci_core_volume_attachment.data[
              one([for key, item in local.block_volume_specs : key if local.block_volume_ids[key] == volume_id])
            ].port,
          ),
          null,
        )
        provider_attachment_id = oci_core_volume_attachment.data[
          one([for key, item in local.block_volume_specs : key if local.block_volume_ids[key] == volume_id])
        ].id
        provider_volume_id = volume_id
        requested_path = try(
          oci_core_volume_attachment.data[
            one([for key, item in local.block_volume_specs : key if local.block_volume_ids[key] == volume_id])
          ].device,
          null,
        )
        retention   = host.storage.block_volume.retention
        size_gib    = host.storage.block_volume.size_gib
        vpus_per_gb = host.storage.block_volume.vpus_per_gb
      }
    ]
  }

  storage_devices = {
    for logical_id, host in local.hosts_by_id : logical_id => (
      host.storage.selected_backend == "local-nvme"
      ? local.local_storage_devices[logical_id]
      : (
        host.storage.selected_backend == "block-volume"
        ? local.block_storage_devices[logical_id]
        : []
      )
    )
  }

  storage_mount_points = {
    scylla     = "/var/lib/scylla"
    manager    = "/var/lib/scylla-manager"
    monitoring = "/var/lib/scylla-monitoring"
  }
}

output "host_manifest" {
  description = "Strict stable host, routing, and provisional storage evidence."
  value = {
    schema_version = "deploy-scylla-vms.host-manifest/v1"
    cluster_uuid   = var.deploy_scylla_vms_input.cluster_uuid
    hosts = tolist([
      for logical_id in sort(keys(local.hosts_by_id)) : {
        logical_id        = logical_id
        role              = local.hosts_by_id[logical_id].role
        zone              = local.hosts_by_id[logical_id].zone
        provider_id       = oci_core_instance.host[logical_id].id
        private_address   = oci_core_instance.host[logical_id].private_ip
        public_address    = oci_core_instance.host[logical_id].public_ip
        jump_host_id      = local.host_jump_ids[logical_id]
        scylla_datacenter = local.hosts_by_id[logical_id].scylla_datacenter
        scylla_rack       = local.hosts_by_id[logical_id].scylla_rack
        shape             = local.hosts_by_id[logical_id].shape
        storage = {
          schema_version        = "deploy-scylla-vms.storage-manifest/v1"
          requested_backend     = local.hosts_by_id[logical_id].storage.requested_backend
          selected_backend      = local.hosts_by_id[logical_id].storage.selected_backend
          selection_algorithm   = local.hosts_by_id[logical_id].storage.selection_algorithm
          selection_status      = local.hosts_by_id[logical_id].storage.selected_backend == "boot-only" ? "final" : "provisional"
          policy_digest         = local.hosts_by_id[logical_id].storage.policy_digest
          storage_generation    = 1
          expected_device_count = length(local.storage_devices[logical_id])
          raw_total_gib         = sum([for device in local.storage_devices[logical_id] : device.size_gib])
          usable_total_gib      = sum([for device in local.storage_devices[logical_id] : device.size_gib])
          layout                = local.hosts_by_id[logical_id].storage.layout
          raid_device           = null
          filesystem_type       = local.hosts_by_id[logical_id].storage.selected_backend == "boot-only" ? null : "xfs"
          filesystem_label      = local.hosts_by_id[logical_id].storage.selected_backend == "boot-only" ? null : "dsv-${substr(sha256(logical_id), 0, 16)}"
          mount_strategy        = local.hosts_by_id[logical_id].storage.selected_backend == "boot-only" ? null : "filesystem-uuid"
          mount_point           = try(local.storage_mount_points[local.hosts_by_id[logical_id].role], null)
          mount_options         = tolist(local.hosts_by_id[logical_id].storage.selected_backend == "boot-only" ? [] : ["noatime"])
          role_allocations      = tolist(local.hosts_by_id[logical_id].storage.selected_backend == "boot-only" ? [] : ["data"])
          devices               = tolist(local.storage_devices[logical_id])
        }
      }
    ])
  }
}
