resource "hetznerrobot_os_rescue" "test" {
  server_name = "test"
  server_id   = "1234567"
}

# host_key_fingerprints exposes the verified MD5 fingerprints reported by
# the Hetzner API for the rescue system, keyed by SSH key algorithm.
output "rescue_host_key_fingerprints" {
  value = hetznerrobot_os_rescue.test.host_key_fingerprints
}

# host_keys provides the verified public keys in authorized_keys format,
# keyed by SSH key algorithm, ready to feed directly into a connection
# block so subsequent SSH sessions don't fail with a host-key mismatch.
resource "null_resource" "post_rescue" {
  triggers = {
    rescue_id = hetznerrobot_os_rescue.test.id
  }

  connection {
    type     = "ssh"
    host     = hetznerrobot_os_rescue.test.ip
    user     = "root"
    password = hetznerrobot_os_rescue.test.ssh_password
    host_key = hetznerrobot_os_rescue.test.host_keys["ssh-ed25519"]
  }

  provisioner "remote-exec" {
    inline = ["uname -a"]
  }
}
