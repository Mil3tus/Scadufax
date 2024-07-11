# network module
# created by mr.n1k0v

# required libraries syn scan function
from logging import getLogger, ERROR # import logging things
getLogger("scapy.runtime").setLevel(ERROR) # get rid if ipv6 packet
from scapy.all import * # scapy library
import time
import socket

# scapy variables
# hide scapy output
conf.verb = 0

### IMPORTANTE
### CONSULTAR ANTES DE CONTINUAR O CODIGO
# https://www.infosecinstitute.com/resources/hacking/port-scanning-using-scapy/
def send_syn_packet(source_address, target_address, source_port, destination_port, syn_timeout):
        start_runtime = time.time()
        syn_scan_packet = sr1(IP(src = source_address, dst = target_address)/TCP(sport = source_port,
        dport = int(destination_port), flags = "S"), timeout = syn_timeout) # built SYN packet
        try:
            # send packet
            syn_packet_code = syn_scan_packet.getlayer(TCP)
            # received a SYN/ACK packet from request
            if 'SA' in str(syn_packet_code):
                # get the service identified on packet
                convert_syn_packet = str(syn_packet_code)
                explode_syn_packet_code = convert_syn_packet.split(':',)
                generate_service_name = explode_syn_packet_code[1].split('>',)
                generated_service = generate_service_name[0].strip()
                # return service name or not
                if (generated_service == str(destination_port)):
                    return str(destination_port), 'open', 'unkown service'
                else:
                    return str(destination_port), 'open', str(generated_service).strip()
            # received a RST/ACK packet from request
            elif 'RA' in str(syn_packet_code):
                # get the service identified on packet
                convert_syn_packet = str(syn_packet_code)
                explode_syn_packet_code = convert_syn_packet.split(':',)
                generate_service_name = explode_syn_packet_code[1].split('>',)
                generated_service = generate_service_name[0].strip()
                if (generated_service == str(destination_port)):
                    return str(destination_port), 'closed', 'unkown service'
                else:
                    return str(destination_port), 'closed', str(generated_service).strip()
        except Exception as e:
            end_runtime = time.time() - start_runtime
            if (int(end_runtime) >= syn_timeout):
                return str(destination_port), 'filtered', 'unkown service'
            else:
                pass


# three way handshake connection function
def tcp_send_packet(target_address, source_port, destination_port, socket_timeout):
    start_runtime = time.time()
    socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket1.settimeout(socket_timeout)
    try:
        socket1.bind(('', destination_port))
        socket1.connect((target_address, destination_port))
        return str(destination_port), 'open', 'unkown service'
    except Exception as e:
        end_runtime = time.time() - start_runtime
        if (int(end_runtime) == socket_timeout):
            return str(destination_port), 'filtered', 'unkown service'
        else:
            return str(destination_port), 'closed', 'unkown service'


# function to generate a random value from source port
# when the user doesn't use the --source-port flag
def random_source_port():
    source_port_random = []
    for i in range(1, 65535):
        source_port_random.append(i)
    source_port = random.choice(source_port_random)
    return source_port


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