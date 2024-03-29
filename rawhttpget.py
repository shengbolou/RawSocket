import socket, sys
from struct import *


def checksum(msg):
    s = 0
    for i in range(0, len(msg)-1, 2):
        tmp = (msg[i + 1]<<8) + msg[i]
        s += tmp
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


source_ip = '10.0.2.15'
dest_ip = socket.gethostbyname("www-edlab.cs.umass.edu")
print(dest_ip)


try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error:
    sys.exit()

def send(data, seq, ack_seq, syn, ack):
    packet = ''

    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 54321   #Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0    # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton ( dest_ip )

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    # tcp header fields
    tcp_source = 1234   # source port
    tcp_dest = 80   # destination port
    tcp_seq = seq
    tcp_ack_seq = ack_seq
    tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    tcp_fin = 0
    tcp_syn = syn
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = ack
    tcp_urg = 0
    tcp_window = socket.htons (5840)    #   maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

    user_data = data

    # pseudo header fields
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header + user_data
    tcp_check = checksum(psh)
    #print tcp_checksum

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)

    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header + user_data

    #Send the packet finally - the port specified has no effect
    s.sendto(packet, (dest_ip , 0 ))


send(b"hello1",454,0,1,0)

try:
    receiveSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error:
    sys.exit()

count=0

while(True):

    response = receiveSocket.recvfrom(65565)
    resPacket = response[0]
    iph = resPacket[0:20]
    source = socket.inet_ntoa(iph[12:16])
    if source == dest_ip:

        tcp_data = resPacket[20:49]
        print(tcp_data.hex())

        seq_num = int.from_bytes(tcp_data[4:8],byteorder='big')
        ack_num = int.from_bytes(tcp_data[8:12],byteorder='big')

        print(seq_num)
        print(ack_num)
        flags = tcp_data[12:14]
        if count==0:
            send(b"GET", 0, seq_num+1, 0, 1)
            count+=1








