provider "oci" {
  region = var.region
}

locals {
  instances = {
    for name, config in var.instances :
    name => {
      openclaw_version = config.openclaw_version
      ocpus            = config.ocpus
      memory_in_gbs    = config.memory_in_gbs
      gateway_port     = config.gateway_port
    }
  }

  gateway_ports = toset([for _, config in local.instances : config.gateway_port])

  ssh_rules = flatten([
    for cidr in var.ssh_ingress_cidrs : [{
      cidr = cidr
      port = 22
      kind = "ssh"
    }]
  ])

  gateway_rules = flatten([
    for cidr in var.gateway_ingress_cidrs : [
      for port in local.gateway_ports : {
        cidr = cidr
        port = port
        kind = "gateway"
      }
    ]
  ])
}

resource "oci_core_vcn" "calibration" {
  compartment_id = var.compartment_ocid
  cidr_block     = var.vcn_cidr_block
  display_name   = "openclaw-calibration-vcn"
  dns_label      = "clawlab"
}

resource "oci_core_internet_gateway" "calibration" {
  compartment_id = var.compartment_ocid
  display_name   = "openclaw-calibration-igw"
  enabled        = true
  vcn_id         = oci_core_vcn.calibration.id
}

resource "oci_core_route_table" "calibration" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.calibration.id
  display_name   = "openclaw-calibration-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.calibration.id
  }
}

resource "oci_core_security_list" "calibration" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.calibration.id
  display_name   = "openclaw-calibration-sl"

  egress_security_rules {
    destination      = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    protocol         = "all"
  }

  dynamic "ingress_security_rules" {
    for_each = local.ssh_rules
    content {
      description = "SSH access"
      protocol    = "6"
      source      = ingress_security_rules.value.cidr
      source_type = "CIDR_BLOCK"

      tcp_options {
        min = ingress_security_rules.value.port
        max = ingress_security_rules.value.port
      }
    }
  }

  dynamic "ingress_security_rules" {
    for_each = local.gateway_rules
    content {
      description = "OpenClaw gateway exposure for black-box calibration"
      protocol    = "6"
      source      = ingress_security_rules.value.cidr
      source_type = "CIDR_BLOCK"

      tcp_options {
        min = ingress_security_rules.value.port
        max = ingress_security_rules.value.port
      }
    }
  }
}

resource "oci_core_subnet" "calibration" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_vcn.calibration.id
  cidr_block                 = var.subnet_cidr_block
  display_name               = "openclaw-calibration-public-subnet"
  dns_label                  = "publiclab"
  route_table_id             = oci_core_route_table.calibration.id
  security_list_ids          = [oci_core_security_list.calibration.id]
  prohibit_public_ip_on_vnic = false
}

resource "random_password" "gateway_token" {
  for_each = local.instances

  length  = 32
  special = false
}

resource "oci_core_instance" "node" {
  for_each = local.instances

  availability_domain = var.availability_domain
  compartment_id      = var.compartment_ocid
  display_name        = each.key
  shape               = var.instance_shape
  state               = "RUNNING"

  shape_config {
    ocpus         = each.value.ocpus
    memory_in_gbs = each.value.memory_in_gbs
  }

  create_vnic_details {
    assign_public_ip = true
    subnet_id        = oci_core_subnet.calibration.id
  }

  source_details {
    source_id               = var.image_ocid
    source_type             = "image"
    boot_volume_size_in_gbs = var.boot_volume_size_gbs
  }

  metadata = {
    ssh_authorized_keys = var.ssh_authorized_keys
    user_data = base64encode(templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
      ssh_username     = var.ssh_username
      openclaw_version = each.value.openclaw_version
      gateway_port     = each.value.gateway_port
      gateway_token    = random_password.gateway_token[each.key].result
    }))
  }

  freeform_tags = {
    purpose           = "openclaw-blackbox-calibration"
    openclaw_version  = each.value.openclaw_version
    gateway_port      = tostring(each.value.gateway_port)
    scanner_ready     = "true"
  }
}

data "oci_core_vnic_attachments" "node" {
  for_each = oci_core_instance.node

  compartment_id = var.compartment_ocid
  instance_id    = each.value.id
}

data "oci_core_vnic" "node" {
  for_each = oci_core_instance.node

  vnic_id = data.oci_core_vnic_attachments.node[each.key].vnic_attachments[0].vnic_id
}
