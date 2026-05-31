resource "hetznerrobot_firewall" "firewall" {
  server_id     = 1234567
  active        = true
  whitelist_hos = true

  rule {
    name     = "icmp"
    protocol = "icmp"
    action   = "accept"
  }

  rule {
    name     = "ssh"
    protocol = "tcp"
    dst_port = "22"
    action   = "accept"
  }

  rule {
    name   = "Deny others"
    action = "discard"
  }
}

# Example with IPv6 also filtered:
# * set filter_ipv6 = true
# * add explicit rules with ip_version = "ipv6" alongside the ipv4 rules
resource "hetznerrobot_firewall" "firewall_ipv6" {
  server_id     = 7654321
  active        = true
  whitelist_hos = true
  # Set true to also evaluate IPv6 packets against the rule list.
  # When false (default), IPv6 traffic bypasses all rules.
  filter_ipv6 = true

  rule {
    ip_version = "ipv4"
    name       = "ssh-v4"
    protocol   = "tcp"
    dst_port   = "22"
    action     = "accept"
  }

  rule {
    ip_version = "ipv6"
    name       = "ssh-v6"
    protocol   = "tcp"
    dst_port   = "22"
    action     = "accept"
  }

  rule {
    name   = "Deny others"
    action = "discard"
  }
}
