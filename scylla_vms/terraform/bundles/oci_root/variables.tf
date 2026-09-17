variable "deploy_scylla_vms_input" {
  description = "Validated non-credential OCI deployment intent."

  type = object({
    schema_version = string
    cluster_uuid   = string
    cluster_name   = string
    provider       = string
    region         = string
    compartment_id = string
    public_ssh_key = string
    image_filters = map(object({
      operating_system         = string
      operating_system_version = string
      version_match            = string
    }))
    network = object({
      mode                    = string
      vcn_id                  = string
      subnet_ids              = map(string)
      vcn_cidr                = string
      private_subnet_cidrs    = map(string)
      public_subnet_cidrs     = map(string)
      operator_cidrs          = list(string)
      allow_public_jump_hosts = bool
    })
    hosts = list(object({
      logical_id         = string
      role               = string
      zone               = string
      shape              = string
      image_id           = string
      image_name         = string
      image_time_created = string
      subnet_id          = string
      subnet_key         = string
      assign_public_ip   = bool
      scylla_datacenter  = string
      scylla_rack        = string
      freeform_tags      = map(string)
      storage = object({
        requested_backend           = string
        selected_backend            = string
        selection_algorithm         = string
        policy_digest               = string
        layout                      = string
        local_min_device_count      = number
        local_min_total_gib         = number
        provider_local_device_count = number
        provider_local_total_gib    = number
        block_volume = object({
          count                 = number
          size_gib              = number
          vpus_per_gb           = number
          attachment_type       = string
          retention             = string
          key_id                = string
          in_transit_encryption = bool
          chap_enabled          = bool
        })
      })
    }))
  })

  validation {
    condition     = var.deploy_scylla_vms_input.schema_version == "deploy-scylla-vms.terraform-input.oci/v2"
    error_message = "The OCI Terraform input schema version is unsupported."
  }

  validation {
    condition     = var.deploy_scylla_vms_input.provider == "oci"
    error_message = "The provider identity must be oci."
  }

  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.deploy_scylla_vms_input.cluster_uuid))
    error_message = "The cluster UUID must be a canonical UUIDv4."
  }

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,62}$", var.deploy_scylla_vms_input.cluster_name)) && !strcontains(var.deploy_scylla_vms_input.cluster_name, "--") && !endswith(var.deploy_scylla_vms_input.cluster_name, "-")
    error_message = "The cluster name is invalid."
  }

  validation {
    condition     = can(regex("^ocid1\\.compartment\\.", var.deploy_scylla_vms_input.compartment_id))
    error_message = "The compartment identifier must be an OCI compartment OCID."
  }

  validation {
    condition     = can(regex("^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$", var.deploy_scylla_vms_input.region))
    error_message = "The OCI region identifier is invalid."
  }

  validation {
    condition     = can(regex("^(?:ecdsa-sha2-nistp(?:256|384|521)|sk-ecdsa-sha2-nistp256@openssh\\.com|sk-ssh-ed25519@openssh\\.com|ssh-ed25519|ssh-rsa) [A-Za-z0-9+/]+={0,3}(?: [^\\r\\n]*)?$", var.deploy_scylla_vms_input.public_ssh_key))
    error_message = "The public SSH key must use one approved OpenSSH public-key algorithm."
  }

  validation {
    condition     = length(var.deploy_scylla_vms_input.hosts) > 0 && length(distinct([for host in var.deploy_scylla_vms_input.hosts : host.logical_id])) == length(var.deploy_scylla_vms_input.hosts)
    error_message = "Hosts must have unique stable logical IDs."
  }

  validation {
    condition = (
      contains(["create", "existing"], var.deploy_scylla_vms_input.network.mode) &&
      alltrue([
        for cidr in var.deploy_scylla_vms_input.network.operator_cidrs :
        can(cidrhost(cidr, 0)) && cidr != "0.0.0.0/0" && cidr != "::/0"
      ]) &&
      length(distinct(var.deploy_scylla_vms_input.network.operator_cidrs)) == length(var.deploy_scylla_vms_input.network.operator_cidrs)
    )
    error_message = "The network mode and canonical bounded operator CIDRs are invalid."
  }

  validation {
    condition = (
      var.deploy_scylla_vms_input.network.mode == "create"
      ? (
        var.deploy_scylla_vms_input.network.vcn_id == null &&
        length(var.deploy_scylla_vms_input.network.subnet_ids) == 0 &&
        var.deploy_scylla_vms_input.network.vcn_cidr != null &&
        can(cidrhost(var.deploy_scylla_vms_input.network.vcn_cidr, 0)) &&
        length(var.deploy_scylla_vms_input.network.private_subnet_cidrs) > 0
      )
      : (
        can(regex("^ocid1\\.vcn\\.", var.deploy_scylla_vms_input.network.vcn_id)) &&
        length(var.deploy_scylla_vms_input.network.subnet_ids) > 0 &&
        alltrue([
          for subnet_id in values(var.deploy_scylla_vms_input.network.subnet_ids) :
          can(regex("^ocid1\\.subnet\\.", subnet_id))
        ]) &&
        var.deploy_scylla_vms_input.network.vcn_cidr == null &&
        length(var.deploy_scylla_vms_input.network.private_subnet_cidrs) == 0 &&
        length(var.deploy_scylla_vms_input.network.public_subnet_cidrs) == 0
      )
    )
    error_message = "Managed and existing network selectors must remain mutually exclusive."
  }

  validation {
    condition = (
      var.deploy_scylla_vms_input.network.allow_public_jump_hosts
      ? (
        length(var.deploy_scylla_vms_input.network.operator_cidrs) > 0 &&
        anytrue([for host in var.deploy_scylla_vms_input.hosts : host.role == "jump-host"])
      )
      : length(var.deploy_scylla_vms_input.network.public_subnet_cidrs) == 0
    )
    error_message = "Public network intent is restricted to explicit jump hosts with bounded operator CIDRs."
  }

  validation {
    condition = alltrue([
      for role, filter in var.deploy_scylla_vms_input.image_filters :
      contains(["scylla", "manager", "monitoring", "jump-host"], role) &&
      length(filter.operating_system) > 0 &&
      length(filter.operating_system_version) > 0 &&
      contains(["exact", "prefix"], filter.version_match)
    ])
    error_message = "Every image filter must name a supported role and explicit OS/version policy."
  }

  validation {
    condition = (
      length(setsubtract(toset(keys(var.deploy_scylla_vms_input.image_filters)), toset([for host in var.deploy_scylla_vms_input.hosts : host.role]))) == 0 &&
      length(setsubtract(toset([for host in var.deploy_scylla_vms_input.hosts : host.role]), toset(keys(var.deploy_scylla_vms_input.image_filters)))) == 0
    )
    error_message = "Image filters must cover every deployed host role exactly."
  }

  validation {
    condition = alltrue([
      for host in var.deploy_scylla_vms_input.hosts :
      can(regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", host.logical_id)) &&
      contains(["scylla", "manager", "monitoring", "jump-host"], host.role) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", host.zone)) &&
      length(host.shape) > 0 &&
      ((host.subnet_id == null) != (host.subnet_key == null)) &&
      (!host.assign_public_ip || host.role == "jump-host") &&
      (host.role == "scylla" ? host.scylla_datacenter != null && host.scylla_rack != null : host.scylla_datacenter == null && host.scylla_rack == null) &&
      can(regex("^ocid1\\.image\\.", host.image_id)) &&
      length(host.image_name) > 0 &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ssZ", host.image_time_created)) &&
      contains(["auto", "local-nvme", "block-volume", "boot-only"], host.storage.requested_backend) &&
      contains(["local-nvme", "block-volume", "boot-only"], host.storage.selected_backend) &&
      (host.storage.requested_backend == "auto" || host.storage.requested_backend == host.storage.selected_backend) &&
      can(regex("^sha256:[0-9a-f]{64}$", host.storage.policy_digest))
    ])
    error_message = "A host violates the stable identity, placement, network, topology, or storage contract."
  }
}

variable "deploy_scylla_vms_metadata" {
  description = "Generation and digest binding for the generated tfvars record."

  type = object({
    schema_version = string
    generation     = number
    cluster_uuid   = string
    cluster_name   = string
    provider       = string
    captured_at    = string
    input_digest   = string
  })

  validation {
    condition     = var.deploy_scylla_vms_metadata.schema_version == "deploy-scylla-vms.tfvars/v1"
    error_message = "The Terraform tfvars envelope schema version is unsupported."
  }

  validation {
    condition     = var.deploy_scylla_vms_metadata.generation >= 1 && floor(var.deploy_scylla_vms_metadata.generation) == var.deploy_scylla_vms_metadata.generation
    error_message = "The Terraform tfvars generation must be a positive integer."
  }

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.deploy_scylla_vms_metadata.input_digest))
    error_message = "The Terraform input digest is invalid."
  }

  validation {
    condition     = can(formatdate("YYYY-MM-DD'T'hh:mm:ssZ", var.deploy_scylla_vms_metadata.captured_at))
    error_message = "The Terraform input capture time is invalid."
  }
}
