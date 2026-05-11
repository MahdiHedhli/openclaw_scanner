variable "region" {
  description = "OCI region for the calibration lab."
  type        = string
}

variable "compartment_ocid" {
  description = "OCI compartment OCID where the calibration lab resources will be created."
  type        = string
}

variable "availability_domain" {
  description = "Availability domain for the calibration instances, for example Uocm:PHX-AD-1."
  type        = string
}

variable "image_ocid" {
  description = "Pinned region-specific Ubuntu image OCID for the chosen region."
  type        = string
}

variable "ssh_authorized_keys" {
  description = "One or more SSH public keys to place on each instance."
  type        = string
}

variable "ssh_username" {
  description = "Login username for the selected image."
  type        = string
  default     = "ubuntu"
}

variable "instance_shape" {
  description = "OCI compute shape to use for the calibration instances."
  type        = string
  default     = "VM.Standard.A1.Flex"
}

variable "vcn_cidr_block" {
  description = "CIDR block for the calibration VCN."
  type        = string
  default     = "10.42.0.0/16"
}

variable "subnet_cidr_block" {
  description = "CIDR block for the public subnet that hosts the calibration nodes."
  type        = string
  default     = "10.42.1.0/24"
}

variable "ssh_ingress_cidrs" {
  description = "CIDR ranges allowed to SSH into the calibration nodes."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "gateway_ingress_cidrs" {
  description = "CIDR ranges allowed to reach the OpenClaw gateway port on calibration nodes."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "boot_volume_size_gbs" {
  description = "Boot volume size in GB for each calibration instance."
  type        = number
  default     = 50
}

variable "instances" {
  description = "Map of calibration nodes to deploy. Keep the total Ampere A1 allocation within the Always Free limits."
  type = map(object({
    openclaw_version = string
    ocpus            = optional(number, 1)
    memory_in_gbs    = optional(number, 6)
    gateway_port     = optional(number, 18789)
  }))

  default = {
    openclaw-2026-2-13 = {
      openclaw_version = "2026.2.13"
      ocpus            = 1
      memory_in_gbs    = 6
      gateway_port     = 18789
    }
    openclaw-2026-2-14 = {
      openclaw_version = "2026.2.14"
      ocpus            = 1
      memory_in_gbs    = 6
      gateway_port     = 18789
    }
    clawdbot-2026-1-24-3 = {
      openclaw_version = "2026.1.24-3"
      ocpus            = 1
      memory_in_gbs    = 6
      gateway_port     = 18789
    }
  }
}
