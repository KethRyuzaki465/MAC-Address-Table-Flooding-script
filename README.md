MAC Address Table Flooding Attack Script using Scapy
====================================================
Uses ARP packets to flood the victim's switch MAC address table.

Features:
  Basic flooding mode
  DHCP snooping bypass mode  
  Custom target/target_MAC/IP support
====================================================
Args:
  target_mac: Target MAC (e.g., default gateway)
  attacker_mac: Attacker's MAC address
  attack_mode: "basic" or "dhcp_snoop_bypass"
  packets_per_second: Attack speed
  duration: Duration in seconds
====================================================
Requirements:
  Scapy
====================================================
Usage:
  python mac_flood.py --target_mac <mac> [--attack mode]
====================================================
Example: python mac_flood.py --target_mac 00:11:22:33:44:55 --mac AA:BB:CC:DD:EE:FF --rate 100 --duration 60
  
