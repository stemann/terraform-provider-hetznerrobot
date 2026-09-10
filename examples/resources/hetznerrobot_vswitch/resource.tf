resource "hetznerrobot_vswitch" "main" {
  name    = "main"
  vlan    = 4000
  servers = [1234567]
}
