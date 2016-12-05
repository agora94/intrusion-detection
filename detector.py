from scapy.all import *
import sys

path = sys.argv[1]
pr = PcapReader(path)


""" Parses pcap file and prints IPs that have
    more than a 3:1 ratio of SYN packets sent
    to SYN-ACK packets received. """
def syn_flood_scan(pr):
    totals = {}
    SYN = 0x02
    SYNACK = 0X12
    for packet in pr:
        try:
            transport_layer = packet[2]
            print packet[0].summary()
            if isinstance(transport_layer, scapy.layers.inet.TCP):
                src = packet[1].src
                dst = packet[1].dst
                flag = transport_layer.flags
                if flag & SYNACK == SYNACK:
                    try:
                        ssent, sarec = totals[dst]
                    except KeyError:
                        ssent, sarec = (0,0)
                    totals[dst] = (ssent, sarec+1)
                elif flag & SYN == SYN:
                    try:
                        ssent, sarec = totals[src]
                    except KeyError:
                        ssent, sarec = (0,0)
                    totals[src] = (ssent+1, sarec)
        except IndexError:
            pass
        
    for ip, tup in totals.iteritems():
        s,sa = tup
        try:
            if s/sa > 3:
                print ip
        except ZeroDivisionError:
            print ip
    return
    
    
syn_flood_scan(pr)