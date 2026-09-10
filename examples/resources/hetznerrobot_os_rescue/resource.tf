resource "hetznerrobot_os_rescue" "test" {
  server_name = "test"
  server_id   = "1234567"
}

output "rescue_host_key_fingerprints" {
  value = hetznerrobot_os_rescue.test.host_key_fingerprints
}

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
