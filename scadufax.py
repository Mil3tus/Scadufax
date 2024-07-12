# scadufax scanner
# created by Mr.N1k0v - 2024

# required libraries
import argparse
import sys
import time
import random
import _thread
import os
import time

# imported modules
sys.path.append('include/')
from network import *
from iostream import *

# set rescursion limit to use _thread function
sys.setrecursionlimit(16323056)


# syn tcp scan target only (192.168.0.1)
def syn_scan_single(single_target_address):
    scadufax_banner()
    # configure other settings before scan
    if (args.script != None):
        program_usage('--script flag cant be used with syn/tcp scan mode')
    else:
        # if timeout not set, 5 by default
        if (args.timeout == None):
            request_timeout = 5
        else:
            request_timeout = int(args.timeout)        

        # if interval between requests not specified
        if (args.i == None):
            interval_request = 1
        else:
            interval_request = float(args.i)

        # if user do not specify --source-port generate a random port number
        if (args.source_port == None):
            source_port_address = random_source_port()
        else:
            source_port_address = int(args.source_port)

        # configure if only open ports will be showed
        if (args.open == True):
            open_only = True
        else:
            open_only = False


        # configure source ip address
        source_ip_address = None

        # configure destination port (default option)
        if (args.p == 'default'):
            destination_port_address = top_ports_default_scanner.split(',',)
        else:
            # generate port list
            destination_port_address = args.p.split(',',)

        # load profile configuration
        load_scadufax_profile(single_target_address, source_port_address, args.p, request_timeout)


        # send parameters for task calc function
        calculated_task = calc_task(request_timeout, interval_request, 1, len(destination_port_address))
        time_left_message(calculated_task)

        # start scanning message
        start_scanning_message()
        
        # verify if host is alive
        icmp_packet = icmp_send_packet(single_target_address, request_timeout)
        if (icmp_packet == True):
            # show target address
            printf_target(single_target_address)

            # read port list
            for port_addr in range(0, len(destination_port_address)):
                time.sleep(int(interval_request))
                destination_port = int(destination_port_address[port_addr])

                # syn packet request
                packet_status = send_syn_packet(source_ip_address, str(single_target_address), int(source_port_address),
                int(destination_port_address[port_addr]), int(request_timeout))
            
                # check packet status values
                if (packet_status != None):
                    packet_port_number = packet_status[0]
                    packet_port_status = packet_status[1]
                    packet_port_service = packet_status[2]
                    # send open port message
                    if (packet_status[1].strip() == 'open'):
                        printf_open(packet_port_number, packet_port_service)
                    elif (packet_status[1].strip() == 'closed'):
                        # check if --open flag is active
                        if (open_only == True):
                            pass
                        else:
                            # if not, show closed ports
                            printf_closed(packet_port_number, packet_port_service)
                    elif (packet_status[1].strip() == 'filtered'):
                        printf_filtered(packet_port_number, packet_port_service)
                    else:
                        pass
        print ('\n')

# syn tcp scan range of addresses (192.168.0.1-192.168.0.254)
def syn_scan_multiple(scan_from, scan_to):
    # configure other settings before scan
    if (args.script != None):
        program_usage('--script flag cant be used with syn/tcp scan mode')
    else:
        # if timeout not set, 5 by default
        if (args.timeout == None):
            request_timeout = 5
        else:
            request_timeout = int(args.timeout)
        
        # if user do not specify --source-port generate a random port number
        if (args.source_port == None):
            source_port_address = random_source_port()
        else:
            source_port_address = int(args.source_port)

        # if interval between requests not specified
        if (args.i == None):
            interval_request = 1
        else:
            interval_request = float(args.i)

        # configure if only open ports will be showed
        if (args.open == True):
            open_only = True
        else:
            open_only = False

        # configure destination port (default option)
        if (args.p == 'default'):
            destination_port_address = top_ports_default_scanner .split(',',)
        else:
            # generate port list
            destination_port_address = args.p.split(',',)

        # configure source ip address
        source_ip_address = None

        # generate ip table
        range_target_address = []   # ip table cache
        range_target_address = generate_ip_range(scan_from, scan_to)

        # load profile configuration
        load_scadufax_profile(scan_from + '-' + scan_to, source_port_address, args.p, request_timeout)

        # send parameters for task calc function
        calculated_task = calc_task(request_timeout, interval_request, len(range_target_address), len(destination_port_address))
        time_left_message(calculated_task)

        # start scanning message
        start_scanning_message()

        # read ip table
        for ip_addr in range(0, len(range_target_address)):
            # verify if host is alive
            icmp_packet = icmp_send_packet(range_target_address[ip_addr], request_timeout)
            if (icmp_packet == True):

                # set trigger in order to not print target address multiple times
                multiple_targets_interrupter = True
                #read port list
                for port_addr in range(0, len(destination_port_address)):
                    target_address = str(range_target_address[ip_addr])
                    destination_port = int(destination_port_address[port_addr])

                    # syn packet request
                    packet_status = send_syn_packet(source_ip_address, str(range_target_address[ip_addr]), int(source_port_address),
                    int(destination_port_address[port_addr]), int(request_timeout))
                
                    # check packet status values
                    if (packet_status != None):
                        packet_port_number = packet_status[0]
                        packet_port_status = packet_status[1]
                        packet_port_service = packet_status[2]
                        # send open port message
                        if (packet_status[1].strip() == 'open'):
                            if (multiple_targets_interrupter == True):
                                printf_target(str(range_target_address[ip_addr]))
                                multiple_targets_interrupter = False
                            printf_open(packet_port_number, packet_port_service)
                        elif (packet_status[1].strip() == 'closed'):
                            # check if --open flag is active
                            if (open_only == True):
                                pass
                            else:
                                # if not, show closed ports
                                if (multiple_targets_interrupter == True):  
                                    printf_target(str(range_target_address[ip_addr]))
                                    multiple_targets_interrupter = False
                                printf_closed(packet_port_number, packet_port_service)
                        elif (packet_status[1].strip() == 'filtered'):
                            if (multiple_targets_interrupter == True):
                                printf_target(str(range_target_address[ip_addr]))
                                multiple_targets_interrupter = False
                            printf_filtered(packet_port_number, packet_port_service)
                        else:
                            pass
        print ('\n')
        finish_scanning_message()
        print ('\n')


# three way handshake tcp scan target only (192.168.0.1)
def tcp_scan_single(single_target_address):
    scadufax_banner()
    # if timeout not set, 5 by default
    if (args.timeout == None):
        request_timeout = 5
    else:
        request_timeout = int(args.timeout)        

    # if interval between requests not specified
    if (args.i == None):
        interval_request = 1
    else:
        interval_request = float(args.i)

    # if user do not specify --source-port generate a random port number
    if (args.source_port == None):
        source_port_address = random_source_port()
    else:
        source_port_address = int(args.source_port)

    # configure if only open ports will be showed
    if (args.open == True):
        open_only = True
    else:
        open_only = False    

    # configure destination port (default option)
    if (args.p == 'default'):
        destination_port_address = top_ports_default_scanner.split(',',)
    else:
        # generate port list
        destination_port_address = args.p.split(',',)

    # load profile configuration
    load_scadufax_profile(single_target_address, source_port_address, args.p, request_timeout)

    # send parameters for task calc function
    calculated_task = calc_task(request_timeout, interval_request, 1, len(destination_port_address))
    time_left_message(calculated_task)

    # start scanning message
    start_scanning_message()
        
    # show target address
    printf_target(single_target_address)

    # read port list
    for port_addr in range(0, len(destination_port_address)):
        time.sleep(int(interval_request))
        destination_port = int(destination_port_address[port_addr])
        # syn packet request
        packet_status = tcp_send_packet(str(single_target_address), int(source_port_address),
        int(destination_port_address[port_addr]), int(request_timeout))

        # check packet status values
        if (packet_status != None):
            packet_port_number = packet_status[0]
            packet_port_status = packet_status[1]
            packet_port_service = packet_status[2]
            # send open port message
            if (packet_status[1].strip() == 'open'):
                printf_open(packet_port_number, packet_port_service)
            elif (packet_status[1].strip() == 'closed'):
                # check if --open flag is active
                if (open_only == True):
                    pass
                else:
                    # if not, show closed ports
                    printf_closed(packet_port_number, packet_port_service)
            elif (packet_status[1].strip() == 'filtered'):
                printf_filtered(packet_port_number, packet_port_service)
            else:
                pass
    print ('\n')
    finish_scanning_message()
    print ('\n')




# second layer of parameters reading
def first_layer():
    # syn scanner selected
    if (args.syn_scanner == True):
        # multiple targets selected
        if (args.R != None):
            try:
                # validate the argument
                range_target_address = args.R.split('-')
                scan_from = range_target_address[0].strip() # generate scan from
                scan_to = range_target_address[1].strip()   # generate scan to

                # validate passed ip address
                validate_scan_from = validate_ip_address(scan_from)
                validate_scan_to = validate_ip_address(scan_to)

                if (validate_scan_from != None or validate_scan_to != None):
                    program_usage('invalid ip address')
                else:
                    # ip address ok, start scan
                    syn_scan_multiple(scan_from, scan_to)
            except:
                # wrong value passed
                program_usage('unrecognized arguments')
        elif (args.d != None):
            single_target_address = args.d
            # validate passed ip address
            validate_target_address = validate_ip_address(single_target_address)
            if (validate_target_address != None):
                program_usage('invalid ip address')
            else:
                # ip address ok, start scan
                syn_scan_single(single_target_address)

    # three way handshake selected
    elif (args.tcp_scanner == True):
        if (args.R != None):
            print ('multiple targets selected')
        elif (args.d != None):
            single_target_address = args.d
            # validate passed ip address
            validate_target_address = validate_ip_address(single_target_address)
            if (validate_target_address != None):
                program_usage('invalid ip address')
            else:
                tcp_scan_single(single_target_address)
        


# main function
def main():
    # global variables
    global args

    # address configuration
    global single_target_address
    global range_target_address
    global scan_from
    global scan_to
    global source_ip_address
    global multiple_targets_interrupter

    # ports configuration
    global destination_port_address
    global source_port_address
    global top_ports_default_scanner

    # other options
    global request_timeout
    global interval_request
    global attack_script
    global output_file
    global open_only

    # set variables
    top_ports_default_scanner = '21,22,23,25,53,80,135,137,139,443,445,3306,8080'


    # parse code for execution options
    parser = argparse.ArgumentParser(description='Scadufax Network Scanner')
    parser.add_argument('-s', dest='syn_scanner', action='store_true',
                        help='scan tcp/syn mode [no Proxychains / Sudo required]')
    parser.add_argument('-t', dest='tcp_scanner', action='store_true',
                        help='three way handshake scan mode')
    parser.add_argument('-d', metavar='192.168.0.1', type=str,
                        help='single target')
    parser.add_argument('-R', metavar='X.X.X.1-X.X.X.254', type=str,
                        help='range of targets')
    parser.add_argument('-p', metavar='21 or 21,22,25', type=str,
                        help='port number, range or default (top ports)')
    parser.add_argument('--source-port', metavar='443', type=str,
                        help='IDS/IPS/Firewall evasion')
    parser.add_argument('--timeout', metavar='1-10', type=str,
                        help='set request timeout')
    parser.add_argument('--script', metavar='<script>', type=str,
                        help='--script help for list')
    parser.add_argument('-i', metavar='0.1-10', type=str,
                        help='interval between each request')
    parser.add_argument('--open', help='show only open ports', action='store_true')
    parser.add_argument('-o', metavar='scan_result.txt', type=str,
                        help='output file')

    args = parser.parse_args()

    # verify if user do not pass any argument
    if not len(sys.argv[1:]):
        program_usage('')
    else:
        if (args.syn_scanner == True and args.tcp_scanner == True):
            program_usage('select only one method to scan')
        elif (args.syn_scanner == True and args.tcp_scanner == False or args.syn_scanner == False and args.tcp_scanner == True):
            if (args.d != None and args.R != None):
                program_usage('you may select only one option')
            else:
                if (args.d == None and args.R == None):
                    # no target selected (single of multiples)
                    program_usage('no target selected')
                else:
                    # everything its ok, call the first layer
                    first_layer()
        elif (args.syn_scanner == False and args.tcp_scanner == False):
            first_layer()  
            try:
                if (args.script.lower() == 'help'):
                    # script module help message
                    print ('ftp\tftp banner, try default credentials, check exploits')
                    print ('http\tget http banner, webspider, webserver software, waf')
                    print ('all\tuse all scripts against the target')
                    print (colored('\nwarning: script mode only works with three way handshake scan mode', 'red', attrs=['bold']))
            except:
                pass

# start here
main()
