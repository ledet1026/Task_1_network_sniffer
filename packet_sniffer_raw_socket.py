import socket 
import struct
import textwrap
import datetime 
TAB_1='\t    '
TAB_2='\t\t    '
TAB_3='\t\t\t    '
TAB_4='\t\t\t\t    '

DATA_TAB_1='\t  '
DATA_TAB_2='\t\t  '
DATA_TAB_3='\t\t\t  '
DATA_TAB_4='\t\t\t\t  '
def main():
    try:
        protocol_filter= input("Enter protocol to filter (icmp, tcp, udp, all: ").lower()
        conn=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
        while True:
            try:
                raw_data,addr=conn.recvfrom(65536)
                dest_mac,sour_mac ,eth_prot, act_data =ethernet_frame(raw_data)
                if eth_prot == 8:
                     (version,header_length, ttl, proto, src, target, act_data) = ipv4_packet(act_data)
                     if(
                        (proto== 1 and protocol_filter in ('icmp','all'))or 
                        (proto == 6 and protocol_filter in ('tcp' , 'all')) or
                        (proto ==17 and protocol_filter in ('udp' , 'all' ))
                     ):
                        print('\n'+ '='*80)
                        time= str(datetime.datetime.now())
                        print("Time: ",time)
                        print("\n Ethernet Frame")
                        print(TAB_1+"Destination: {}, Source: {} ,Protocol: {} ".format(dest_mac,sour_mac ,eth_prot))# decode and print
                        print(TAB_1 + 'ipv4 packets')
                        print(TAB_2 + 'version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                        print(TAB_2 + 'Protocol: {}, Source: {}, target: {}'.format(proto, src, target))
            
                        if proto == 1: 
                             icmp_type, code, checksum,act_data=icmp_packet(act_data)
                             print(TAB_1 + 'ICMP Packet: ')
                             print(TAB_2 + 'Type: {}, code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                             print(TAB_2 + 'Data: ')
                             print(format_multi_line(DATA_TAB_3,act_data))


                        elif  proto == 6: 
                             (src_port,dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, act_data)= tcp_segment(act_data)
                             print(TAB_1 + 'TCP Segment: ')
                             print(TAB_2 + 'Source port: {},Destination port: {}'.format(src_port, dest_port))
                             print(TAB_2 + 'Sequence: {},Acknowledgment: {}'.format(sequence, acknowledgment))
                             print(TAB_2 + 'Flags')
                             print(TAB_2 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                             print(TAB_2 + 'Data: ')
                             print(format_multi_line(DATA_TAB_3,act_data))
                        elif proto == 17: 
                             src_port, dest_port, length,act_data = udp_segment(act_data)
                             print(TAB_1 + 'UDP segment : ')
                             print(TAB_2 + 'Source port: {}, Destination port: {}, length: {}'.format(src_port, dest_port, length))
                             print(TAB_2 + 'Data: ')
                             print(format_multi_line(DATA_TAB_3,act_data))
                        else: 
                             print(TAB_1 + 'data: ')
                             print(format_multi_line(DATA_TAB_3, act_data))    
            except KeyboardInterrupt:
                print("\n[!] Packet capture interrupt by user.")
                break
            except Exception as e:
                print(f"Error occurred while capturing : {e}")
    except Exception as main_error:
        print(f"[!] Failed to start packet sniffer: {main_error}")     

def ethernet_frame(data):
    dest_mac, src_mac , proto = struct.unpack('!6s6sH',data[:14])#helps to devide the first byte of the ethernet frame 
    return get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto), data[14:]

def get_mac_addr(mac_bytes):
    return ':'.join(format(b,'02x')for b in mac_bytes).upper()

def ipv4_packet(data):
    version_header_length=data[0]
    version=version_header_length >>4
    header_length=(version_header_length & 15) *4
    ttl, proto ,src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str,addr))

def icmp_packet(data):
    icmp_type, code, checksum= struct.unpack('! B B H ', data[:4])
    return icmp_type, code, checksum, data[4:]
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags)= struct.unpack('! H H L L H', data[:14])
    offset=(offset_reserved_flags >>12) * 4
    flag_urg=(offset_reserved_flags & 32) >> 5
    flag_ack=(offset_reserved_flags & 16) >> 4
    flag_psh=(offset_reserved_flags & 8) >> 3
    flag_rst=(offset_reserved_flags & 4) >> 2
    flag_syn=(offset_reserved_flags & 2) >> 1
    flag_fin=offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,data[offset:]
def udp_segment(data):
    src_port,dest_port, size =struct.unpack('!H H 2x H',data[:8])
    return src_port, dest_port, size, data[8:]
def format_multi_line(prefix, string,size=80):
    width=size-len(prefix)
    if isinstance(string,bytes):
        string=' '.join(r'\x{:02x}'.format(byte) for byte in string)
        if size  % 2:
            size -=1
    return '\n'.join([prefix+line for line in textwrap.wrap(string,size)])
 
main()
