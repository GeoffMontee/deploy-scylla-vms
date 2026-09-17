locals {
  hosts_by_id = {
    for host in var.deploy_scylla_vms_input.hosts : host.logical_id => host
  }

  image_queries = {
    for key in distinct([
      for host in var.deploy_scylla_vms_input.hosts : "${host.role}|${host.shape}"
      ]) : key => {
      role  = split("|", key)[0]
      shape = split("|", key)[1]
    }
  }
}

data "oci_core_images" "role_shape" {
  for_each = local.image_queries

  compartment_id   = var.deploy_scylla_vms_input.compartment_id
  operating_system = var.deploy_scylla_vms_input.image_filters[each.value.role].operating_system
  operating_system_version = (
    var.deploy_scylla_vms_input.image_filters[each.value.role].version_match == "exact"
    ? var.deploy_scylla_vms_input.image_filters[each.value.role].operating_system_version
    : null
  )
  shape      = each.value.shape
  state      = "AVAILABLE"
  sort_by    = "TIMECREATED"
  sort_order = "DESC"
}

locals {
  compatible_images = {
    for key, query in local.image_queries : key => [
      for image in data.oci_core_images.role_shape[key].images : image
      if image.state == "AVAILABLE" &&
      image.operating_system == var.deploy_scylla_vms_input.image_filters[query.role].operating_system &&
      (
        var.deploy_scylla_vms_input.image_filters[query.role].version_match == "exact"
        ? image.operating_system_version == var.deploy_scylla_vms_input.image_filters[query.role].operating_system_version
        : startswith(image.operating_system_version, var.deploy_scylla_vms_input.image_filters[query.role].operating_system_version)
      )
    ]
  }

  newest_image_times = {
    for key, images in local.compatible_images :
    key => try(reverse(sort([for image in images : image.time_created]))[0], null)
  }

  newest_images = {
    for key, images in local.compatible_images : key => [
      for image in images : image
      if image.time_created == local.newest_image_times[key]
    ]
  }

  selected_images = {
    for key in keys(local.image_queries) :
    key => try(local.newest_images[key][0], null)
  }
}

check "input_identity_binding" {
  assert {
    condition = (
      var.deploy_scylla_vms_metadata.cluster_uuid == var.deploy_scylla_vms_input.cluster_uuid &&
      var.deploy_scylla_vms_metadata.cluster_name == var.deploy_scylla_vms_input.cluster_name &&
      var.deploy_scylla_vms_metadata.provider == var.deploy_scylla_vms_input.provider
    )
    error_message = "The generated tfvars metadata and OCI input identities conflict."
  }
}

check "network_mode_invariants" {
  assert {
    condition = (
      var.deploy_scylla_vms_input.network.mode == "create"
      ? (
        var.deploy_scylla_vms_input.network.vcn_id == null &&
        length(var.deploy_scylla_vms_input.network.subnet_ids) == 0 &&
        var.deploy_scylla_vms_input.network.vcn_cidr != null &&
        length(var.deploy_scylla_vms_input.network.private_subnet_cidrs) > 0
      )
      : (
        var.deploy_scylla_vms_input.network.mode == "existing" &&
        var.deploy_scylla_vms_input.network.vcn_id != null &&
        length(var.deploy_scylla_vms_input.network.subnet_ids) > 0 &&
        var.deploy_scylla_vms_input.network.vcn_cidr == null &&
        length(var.deploy_scylla_vms_input.network.private_subnet_cidrs) == 0 &&
        length(var.deploy_scylla_vms_input.network.public_subnet_cidrs) == 0
      )
    )
    error_message = "Managed and existing network inputs must remain mutually exclusive."
  }
}

check "image_selection" {
  assert {
    condition = alltrue([
      for key in keys(local.image_queries) :
      length(local.compatible_images[key]) > 0 && length(local.newest_images[key]) == 1
    ])
    error_message = "Each role and shape must resolve to exactly one newest compatible AVAILABLE OCI image."
  }
}

check "selected_image_evidence" {
  assert {
    condition = alltrue([
      for host in var.deploy_scylla_vms_input.hosts :
      try(
        local.selected_images["${host.role}|${host.shape}"].id == host.image_id &&
        local.selected_images["${host.role}|${host.shape}"].display_name == host.image_name &&
        local.selected_images["${host.role}|${host.shape}"].time_created == host.image_time_created,
        false
      )
    ])
    error_message = "The selected OCI image conflicts with the generated host image evidence."
  }
}
