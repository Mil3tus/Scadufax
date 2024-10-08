# network module
# created by Mil3tus

#Default TTL and Hop Limit values vary between different operating systems, here are the defaults for a few:

# Linux kernel 2.4 (circa 2001): 255 for TCP, UDP and ICMP
# Linux kernel 4.10 (2015): 64 for TCP, UDP and ICMP
# Windows XP (2001): 128 for TCP, UDP and ICMP
# Windows 10 (2015): 128 for TCP, UDP and ICMP
# Windows Server 2008: 128 for TCP, UDP and ICMP
# Windows Server 2019 (2018): 128 for TCP, UDP and ICMP
# MacOS (2001): 64 for TCP, UDP and ICMP



# required libraries syn scan function
from logging import getLogger, ERROR # import logging things
getLogger("scapy.runtime").setLevel(ERROR) # get rid if ipv6 packet
from scapy.all import * # scapy library
import time
import socket
from iostream import *

# scapy variables
# hide scapy output
conf.verb = 0


#-------------------------------------------------------------------------------------------------------------------------------------

# send ICMP packet in order to show if host is alive or not
def icmp_send_packet(target_address, icmp_timeout):
    # send ICMP packet
    icmp_packet = sr1(IP(dst = target_address)/ICMP(), timeout = icmp_timeout)
    if (icmp_packet != None):
        # host is alive :)
        return True
    else:
        # host is dead :(
        return False

#-------------------------------------------------------------------------------------------------------------------------------------

# three way handshake connection function (TCP Protocol)
def tcp_send_packet(target_address, source_port, destination_port, socket_timeout):
    start_runtime = time.time()
    socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # this line of code solve this error ([Errno 98] Address already in use)
    socket1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # configure socket timeout
    socket1.settimeout(socket_timeout)
    try:
        # set source port
        socket1.bind(('', source_port))
        socket1.connect((target_address, destination_port))
        # generate service name
        packet_service = generate_service(destination_port, 'tcp')
        # return port status
        socket1.close()
        return str(destination_port), 'open', str(packet_service)
    except Exception as e:
        end_runtime = time.time() - start_runtime
        if (int(end_runtime) == socket_timeout):
            packet_service = generate_service(destination_port, 'tcp')
            # return port status
            socket1.close()
            return str(destination_port), 'filtered', str(packet_service)
        else:
            packet_service = generate_service(destination_port, 'tcp')
            # return port status
            socket1.close()
            return str(destination_port), 'closed', str(packet_service)
        
def udp_send_packet(source_address, target_address, source_port, destination_port, syn_timeout):
    try:
        # send udp packet
        send_packet = sr1(IP(dst = target_address)/UDP(sport = source_port,
        dport = int(destination_port)), timeout = syn_timeout) # built SYN packet
        packet_code = send_packet.getlayer(UDP)
        # 
        if (packet_code == None):
            # generate service from port number
            packet_service = generate_service(destination_port, 'udp')
            # return information with port number, status and service description
            return str(destination_port), 'closed', str(packet_service)
    except Exception as e:
            # generate service from port number
            packet_service = generate_service(destination_port, 'udp')
            # return information with port number, status and service description
            return str(destination_port), 'open/f', str(packet_service)

#-------------------------------------------------------------------------------------------------------------------------------------

# function to generate a random value from source port
# when the user doesn't use the --source-port flag
def random_source_port():
    source_port_random = []
    for i in range(1, 65535):
        source_port_random.append(i)
    source_port = random.choice(source_port_random)
    return source_port

#-------------------------------------------------------------------------------------------------------------------------------------

# generate ip list (from: 192.168.0.1 to: 192.168.0.254)
def generate_ip_range(scan_from, scan_to):
    start = list(map(int, scan_from.split(".")))
    end = list(map(int, scan_to.split(".")))
    temp = start
    ip_range = []
    ip_range.append(scan_from)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 255:
                temp[i] = 1
                temp[i-1] += 1
        ip_range.append(".".join(map(str, temp)))
    return ip_range

#-------------------------------------------------------------------------------------------------------------------------------------

# send flag funtion prototype
def send_flag_prototype(source_address, target_address, source_port, destination_port, syn_timeout, packet_flag):
    start_runtime = time.time()
    # send packet with a custom flag
    send_packet = sr1(IP(src = source_address, dst = target_address)/TCP(sport = source_port,
        dport = int(destination_port), flags = packet_flag), timeout = syn_timeout) # built SYN packet
    
    # SYN Stealth scan code
    # * Send S, if returns SA: Port Open
    # * Send S, if returns RA: Port Closed
    # * Send S, if retuns None: Port Filtered
    if (packet_flag == 'S'):
        try:
            packet_code = send_packet.getlayer(TCP)
            if 'SA' in str(packet_code):
                # generate service from port number
                packet_service = generate_service(destination_port, 'tcp')
                # return information with port number, status and service description
                return str(destination_port), 'open', str(packet_service)
            elif 'RA' in str(packet_code):
                # generate service from port number
                packet_service = generate_service(destination_port, 'tcp')
                # return information with port number, status and service description
                return str(destination_port), 'closed', str(packet_service)
        except Exception as e:
            end_runtime = time.time() - start_runtime
            if (int(end_runtime) >= syn_timeout):
                # generate service from port number
                packet_service = generate_service(destination_port, 'tcp')
                # return information with port number, status and service description
                return str(destination_port), 'filtered', str(packet_service)
            else:
                print (e)
    # FIN scan code
    # * Send F, if returns None: Port Open/Filtered
    # * Send F, if returns RA: Port Closed
    elif (packet_flag == 'F'):
        try:
            packet_code = send_packet.getlayer(TCP)
            if 'RA' in str(packet_code):
                # generate service from port number
                packet_service = generate_service(destination_port, 'tcp')
                # return information with port number, status and service description
                return str(destination_port), 'closed', str(packet_service)
        except Exception as e:
            end_runtime = time.time() - start_runtime
            if (int(end_runtime) >= syn_timeout):
                # generate service from port number
                packet_service = generate_service(destination_port, 'tcp')
                # return information with port number, status and service description
                return str(destination_port), 'open/f', str(packet_service)
            else:
                print (e)
    # NULL scan code
    # * Send N, if returns None: Port Open/Filtered
    # * Send N, if returns RA: Port Closed
    elif (packet_flag == 'N'):
        try:
            packet_code = send_packet.getlayer(TCP)
            if 'RA' in str(packet_code):
                # generate service from port number
                packet_service = generate_service(destination_port, 'tcp')
                # return information with port number, status and service description
                return str(destination_port), 'closed', str(packet_service)
        except Exception as e:
            end_runtime = time.time() - start_runtime
            if (int(end_runtime) >= syn_timeout):
                # generate service from port number
                packet_service = generate_service(destination_port, 'tcp')
                # return information with port number, status and service description
                return str(destination_port), 'open/f', str(packet_service)
            else:
                print (e)     
    # XMAS scan code
    # * Send FPU, if returns None: Port Open/Filtered
    # * Send FPU, if returns RA: Port Closed
    elif (packet_flag == 'FPU'):
        try:
            packet_code = send_packet.getlayer(TCP)
            if 'RA' in str(packet_code):
                # generate service from port number
                packet_service = generate_service(destination_port, 'tcp')
                # return information with port number, status and service description
                return str(destination_port), 'closed', str(packet_service)
        except Exception as e:
            end_runtime = time.time() - start_runtime
            if (int(end_runtime) >= syn_timeout):
                # generate service from port number
                packet_service = generate_service(destination_port, 'tcp')
                # return information with port number, status and service description
                return str(destination_port), 'open/f', str(packet_service)
            else:
                print (e)

