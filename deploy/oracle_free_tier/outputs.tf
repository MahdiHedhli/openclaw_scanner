output "calibration_nodes" {
  description = "Public calibration node inventory without secrets."
  value = {
    for name, instance in oci_core_instance.node :
    name => {
      id               = instance.id
      public_ip        = data.oci_core_vnic.node[name].public_ip_address
      private_ip       = data.oci_core_vnic.node[name].private_ip_address
      openclaw_version = local.instances[name].openclaw_version
      gateway_port     = local.instances[name].gateway_port
      scanner_target   = "${data.oci_core_vnic.node[name].public_ip_address}:${local.instances[name].gateway_port}"
    }
  }
}

output "scanner_targets" {
  description = "List of scanner targets for the calibration nodes."
  value = [
    for name, instance in oci_core_instance.node :
    "${data.oci_core_vnic.node[name].public_ip_address}:${local.instances[name].gateway_port}"
  ]
}

output "gateway_tokens" {
  description = "Gateway auth tokens for the calibration nodes."
  sensitive   = true
  value = {
    for name, value in random_password.gateway_token :
    name => value.result
  }
}
