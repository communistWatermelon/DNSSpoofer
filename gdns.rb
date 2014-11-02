#!/usr/bin/ruby
require 'rubygems'
require 'packetfu'
include PacketFu

def puts_dns(text)
  user = File.open("thing.txt", "a") 
  puts "File opened!"
  user.puts("---------------------")
  user.puts(text)
  user.puts(text.unpack('H*'))
  user.close
end

def newDnsResponse()
  # build most of a dns packet
end

def finalizeDnsResponse()
  # put in the id, ip, and src/dst ports
end


def isQuery(packet)
  dnsFlag = (packet.payload[2]).to_s + (packet.payload[3]).to_s
  qryFlag = "\x01\x00"
  if dnsFlag == qryFlag
    return true
  end

  return false
end

def dns_query_grabber()
  puts "Waiting for queries:"
  capture_session = PacketFu::Capture.new(:iface => $iface, :start => true, :promisc => true, :filter => "udp and port 53 and src " + $tIP, :save => true)
  capture_session.stream.each { |packet|
    pkt = Packet.parse(packet)
    if isQuery(pkt)

      # get src and dst port from udp
      udpSrc = pkt.udp_src
      udpDst = pkt.udp_dst

      # get transaction id from dns
      queryID = pkt.payload[0, 2]
      # puts(queryID.unpack('H*'))

      name = ""
      num = (pkt.payload[12]).to_s.ord    

      k = 0
      while num > 0 
        for i in 1..num
          name += pkt.payload[12+i+k]
        end

        k += num+1        
        num = pkt.payload[12+k].to_s.ord
        
        if num != 0
          name += '.'
        end
      end

      puts "name: #{name}"
      # get name from dns
      # craft dns packet
      # send dns packet
      #finalizeDnsResponse()

      # packet_info = [pkt.ip_saddr, pkt.ip_daddr]
      # puts_dns(packet)
    end
  }
end
