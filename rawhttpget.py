import socket, sys
import random
from struct import *


source_ip = '10.0.2.15'

dest_ip = socket.gethostbyname("elsrv2.cs.umass.edu")
print dest_ip

try:
    sendSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error, msg:
    print
    'Send socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

try:
    receiveSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error, msg:
    print
    'Receive socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        tmp = (ord(msg[i + 1])<<8) + ord(msg[i])
        s += tmp
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff



def generate_ip_header():
    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = random.randint(1, 10000)  # Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(source_ip)  # Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
                     ip_saddr, ip_daddr)
    return ip_header


def generate_tcp_header(seq, ack_seq, syn, ack, fin=0, rst=0, psh=0, data=""):
    # tcp header fields
    tcp_source = 1234  # source port
    tcp_dest = 80  # destination port
    tcp_seq = seq
    tcp_ack_seq = ack_seq
    tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
    # tcp flags
    tcp_fin = fin
    tcp_syn = syn
    tcp_rst = rst
    tcp_psh = psh
    tcp_ack = ack
    tcp_urg = 0
    tcp_window = socket.htons(5840)  # maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    data_len = len(data)
    data_len = data_len+1 if data_len%2==1 else data_len
    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH'+str(data_len)+"s",
                      tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window,
                      tcp_check, tcp_urg_ptr, data)


    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(str(tcp_header))

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header

    tcp_check = checksum(psh)


    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                      tcp_window) + pack('H', tcp_check) + pack("!H"+str(data_len)+"s", tcp_urg_ptr, data)

    return tcp_header


def validate_tcp_checksum(resPacket, data_len):
    tcph = resPacket[20:]
    tcp_h = unpack('!HHLLBBHHH' + str(data_len) + 's',tcph)
    len = data_len+1 if data_len%2==1 else data_len
    actual_tcph = pack('!HHLLBBHHH' + str(len) + 's',tcp_h[0],tcp_h[1],tcp_h[2],tcp_h[3],
                       tcp_h[4],tcp_h[5],tcp_h[6],tcp_h[7],tcp_h[8],tcp_h[9])
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, data_len+20)
    psh = psh + actual_tcph
    return checksum(psh) == 0


def receive():
    while(True):
        resPacket = receiveSocket.recvfrom(65565)
        # print "raw"
        # print resPacket
        # print
        resPacket = resPacket[0]
        iph = resPacket[0:20]
        source = socket.inet_ntoa(iph[12:16])
        if source == dest_ip and checksum(iph)==0:
            data_len = int(iph[2:4].encode('hex'), 16)-40

            print "correct length? %d" % data_len
            print "formatted"
            print(":".join("{:02x}".format(ord(c)) for c in resPacket))
            print
            print validate_tcp_checksum(resPacket, data_len)
            if validate_tcp_checksum(resPacket, data_len):
                return resPacket


def receive_ack(seq):
    resPacket = receive()
    tcp_header = resPacket[20:40]
    tcp_flag = int(tcp_header[12:14].encode('hex'), 16) & 16
    if tcp_flag==16:
        recv_seq_num = int(tcp_header[4:8].encode('hex'), 16)
        recv_ack_num = int(tcp_header[8:12].encode('hex'), 16)
        if recv_ack_num == seq+1:
            return recv_seq_num, resPacket
        else:
            return False, resPacket

def initialize_conn():
    ip_header = generate_ip_header()
    tcp_header = generate_tcp_header(454, 0, 1, 0)
    packet = ip_header + tcp_header

    sendSocket.sendto(packet, (dest_ip, 0))

    ack, resPacket = receive_ack(454)

    if ack!=False:
        ip_header = generate_ip_header()
        tcp_header = generate_tcp_header(455, ack+1, 0, 1)
        packet = ip_header + tcp_header
        sendSocket.sendto(packet, (dest_ip, 0))
        return ack, 455
    else:
        print "conn error!"


def reset():
    ip_header = generate_ip_header()
    tcp_header = generate_tcp_header(454, 0, 0, 0, rst=1)
    packet = ip_header + tcp_header

    sendSocket.sendto(packet, (dest_ip, 0))

def terminate(seq,ack):
    ip_header = generate_ip_header()
    tcp_header = generate_tcp_header(seq, ack+1, 0, 1, fin=1)
    packet = ip_header + tcp_header

    sendSocket.sendto(packet, (dest_ip, 0))

    recack, resPacket = receive_ack(seq) # receive ack

    if recack != False:
        recack, resPacket = receive_ack(seq) # receive syn-ack

        ip_header = generate_ip_header()
        tcp_header = generate_tcp_header(seq+1, recack+1, 0, 1)
        packet = ip_header + tcp_header
        sendSocket.sendto(packet, (dest_ip, 0))
    else:
        print "terminate error!"

def send_get(ack, seq):
    get_message = "GET / HTTP/1.0\r\nHost: elsrv2.cs.umass.edu\r\n\r\n"
    ip_header = generate_ip_header()
    tcp_header = generate_tcp_header(seq, ack+1, 0, 1, psh=1, data=get_message)
    packet = ip_header+tcp_header
    sendSocket.sendto(packet, (dest_ip, 0))

def receive_file_and_terminate():
    data = ""
    while(True):
        resPacket = receive()
        iph = resPacket[0:20]
        data_len = int(iph[2:4].encode('hex'), 16)-40
        print "data length: %d" % data_len
        tcp_header = resPacket[20:40]
        tcp_flag = int(tcp_header[12:14].encode('hex'), 16) & 25
        print tcp_flag
        if tcp_flag==25: # fin-psh-ack, terminate
            recv_seq_num = int(tcp_header[4:8].encode('hex'), 16)
            recv_ack_num = int(tcp_header[8:12].encode('hex'), 16)
            ip_header = generate_ip_header()
            tcp_header = generate_tcp_header(recv_ack_num, recv_seq_num+data_len, 0, 1)
            packet = ip_header + tcp_header

            sendSocket.sendto(packet, (dest_ip, 0))

            return data
        if data_len>0: # get the data
            data = unpack("!"+str(data_len)+"s", resPacket[40:40+data_len])



ack, seq = initialize_conn()
send_get(ack, seq)
data = receive_file_and_terminate()
# print data
data = data[0]
idx = data.find("\r\n\r\n")
f = open('test.html','wb')
f.write(data[idx+4:])
f.close()


# reset()












