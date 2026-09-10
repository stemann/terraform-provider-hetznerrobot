resource "hetznerrobot_vswitch_servers" "main" {
  vswitch_id = "10000"
  servers    = [1234567]
}

resource "hetznerrobot_vswitch_servers" "unmanaged" {
  vswitch_id        = "100001"
  servers           = [1234567]
  include_unmanaged = true
}
