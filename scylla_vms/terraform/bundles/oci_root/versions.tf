terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 9.1.0"
    }
  }
}

provider "oci" {
  region = var.deploy_scylla_vms_input.region
}
