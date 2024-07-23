# iostream module
# created by Mil3tus

# required libraries
from termcolor import colored
import time
import datetime
import sys

#---------------------------------------------------------
# term color example
#print (colored('hello world', 'green'))
#print (colored('hello world', 'green', attrs=['bold']))

# color grade
# red, black, light_cyan, green, magenta, white, etc

# highlights
# on_black, on_red, on_green, on_white, etc

# attribs
# bold, dark, underline, blink, reverse, and concealed

#---------------------------------------------------------

# task calc until the end of execution
def calc_task(request_timeout, interval_request, address_pool, port_pool):
    # plus time unit (request_timeout + interval_request)
    time_unit = float(request_timeout) + float(interval_request)
    # multiplies time unit * len(port)
    port_unit = time_unit * port_pool
    # multiplies time unit and port pool
    address_pool = address_pool
    time_calc = port_unit * address_pool
    time_calc = time_calc / 2

    if (time_calc > 60):
        # minutes
        time_calc = time_calc / 60
        if (time_calc > 60):
            # hour
            time_calc = time_calc / 60
            return str("{:.1f}".format(time_calc)) + ' hours left'
        else:
            return str("{:.1f}".format(time_calc)) + ' minutes left'
    else:
        # seconds
        time_calc = time_calc
        return str("{:.1f}".format(time_calc)) + ' seconds left'


#-------------------------------------------------------------------------------------------------------------------------------------



# scadufax scanner banner
def scadufax_banner():
    time.sleep(1)
    print ('\n\n')
    print ('\t\t███████╗ ██████╗ █████╗ ██████╗ ██╗   ██╗███████╗ █████╗ ██╗  ██╗')
    print ('\t\t██╔════╝██╔════╝██╔══██╗██╔══██╗██║   ██║██╔════╝██╔══██╗╚██╗██╔╝')
    print ('\t\t███████╗██║     ███████║██║  ██║██║   ██║█████╗  ███████║ ╚███╔╝') 
    print ('\t\t╚════██║██║     ██╔══██║██║  ██║██║   ██║██╔══╝  ██╔══██║ ██╔██╗') 
    print ('\t\t███████║╚██████╗██║  ██║██████╔╝╚██████╔╝██║     ██║  ██║██╔╝ ██╗')
    print ('\t\t╚══════╝ ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝')
    print ('\n\n')

#-------------------------------------------------------------------------------------------------------------------------------------


# show scadufax profile scanning
def load_scadufax_profile(target_address, source_port, destination_port, request_timeout):

    top_ports_default_scanner = '1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,32,' + \
    '33,37,42,43,49,53,70,80,135,137,139,443,445,458,464,464,481,497,' + \
    '500,512,515,524,2020,2121,2222,2323,2424,2525,3005,3006,3007,3031,3052,' + \
    '3306,4443,4550,4567,4662,5288,8080,8081,8082,8083,8084'
    
    
    time.sleep(1)
    print ('\n[', end='')
    print (colored('*', 'green', attrs=['bold']), end='')
    print ('] scanning profile')

    print ('\t[', end='')
    print (colored('>', 'cyan', attrs=['bold']), end='')
    print ('] target address: ' + str(target_address))
    print ('\t[', end='')
    print (colored('>', 'cyan', attrs=['bold']), end='')
    print ('] source port: ' + str(source_port))
    print ('\t[', end='')
    print (colored('>', 'cyan', attrs=['bold']), end='')
    if (destination_port == top_ports_default_scanner):
        print ('] destination port(s): default')
        print ('\t[', end='')
    else:
        print ('] destination port(s): ' + str(destination_port))
        print ('\t[', end='')
    print (colored('>', 'cyan', attrs=['bold']), end='')
    print ('] request timeout: ' + str(request_timeout))



#-------------------------------------------------------------------------------------------------------------------------------------


# time left message
def time_left_message(time_value):
    print ('\n[', end='')
    print (colored('+', 'red', attrs=['bold']), end='')
    print ('] estimated task time [ ' + str(time_value) + ' ]')


#-------------------------------------------------------------------------------------------------------------------------------------


# start scanning message
def start_scanning_message():
    time.sleep(1)
    print ('[', end='')
    print (colored('*', 'green', attrs=['bold']), end='')
    print ('] start scanning [' + str(datetime.datetime.now()) + ']')


#-------------------------------------------------------------------------------------------------------------------------------------


# start scanning message
def finish_scanning_message():
    time.sleep(1)
    print ('[', end='')
    print (colored('*', 'light_cyan', attrs=['bold']), end='')
    print ('] task finished [' + str(datetime.datetime.now()) + ']\n')


#-------------------------------------------------------------------------------------------------------------------------------------


# show target address on screen
def printf_target(target_address):
    print ('\n[', end='')
    print (colored('!', 'yellow', attrs=['bold']), end='')
    print ('] ' + str(target_address))


#-------------------------------------------------------------------------------------------------------------------------------------


def printf_status(port_address, port_service, port_status):
    # print open port status
    if (port_status == 'open'):
        print ('\t', end='')
        print (colored('-', 'white', attrs=['bold']), end=' ')
        print (f"{str(port_address):<5}", end='')
        print (f"{'tcp':<5}", end='')
        print (colored('open', 'green'), end='')
        print (f"{'':<7}", end='')
        print (str(port_service))
    # print closed port status
    elif (port_status == 'closed'):
        print ('\t', end='')
        print (colored('-', 'white', attrs=['bold']), end=' ')
        print (f"{str(port_address):<5}", end='')
        print (f"{'tcp':<5}", end='')
        print (colored('closed', 'red'), end='')
        print (f"{'':<5}", end='')
        print (str(port_service))
    # print filtered port status
    elif (port_status == 'filtered'):
        print ('\t', end='')
        print (colored('-', 'white', attrs=['bold']), end=' ')
        print (f"{str(port_address):<5}", end='')
        print (f"{'tcp':<5}", end='')
        print (colored('filtered', 'yellow'), end='')
        print (f"{'':<3}", end='')
        print (str(port_service))
    # print open/filtered port status
    elif (port_status == 'open/f'):          
        print ('\t', end='')
        print (colored('-', 'white', attrs=['bold']), end=' ')
        print (f"{str(port_address):<5}", end='')
        print (f"{'tcp':<5}", end='')
        print (colored('[open]', 'magenta'), end='')
        print (f"{'':<5}", end='')
        print (str(port_service))      

#-------------------------------------------------------------------------------------------------------------------------------------


# function to validate ip address
# if the function return NO VALUE (None) the ip address is valid
def validate_ip_address(ip_address):
    try:
        explode_ip = ip_address.split('.')
        if (len(explode_ip) < 4):
            # invalid ip address (has no 4 blocks of numbers)
            return 1
        else:
            for i in range(0, 4):
                try:
                    explode_ip[i] = int(explode_ip[i])
                    if (len(str(explode_ip[i])) > 3):
                        # invalid ip address (code fail to convert each block in int variable)
                        return 1
                except:
                    # invalid ip address (has no 4 blocks)
                    return 1
    except:
        # invalid ip address
        return 1


#-------------------------------------------------------------------------------------------------------------------------------------


# error message
def program_usage(error_message):
    print ('usage: scadufax [-h] [-s] [-t] [-d 192.168.0.1] [-R X.X.X.1-X.X.X.254]')
    print ('[-p 21 or 21,22,25] [--source-ip SOURCE_IP] [--source-port 443]')
    print ('[--timeout 1-10] [--script <script>] [-i 0.1-10] [--open]')
    print ('[-o scan_result.txt]')
    if (error_message == ''):
        print ('')
    else:
        print ('error: ' + error_message)



#-------------------------------------------------------------------------------------------------------------------------------------

# generate service from port number
def generate_service(port_number, protocol):

    if (protocol == 'tcp'):
        try:
            # try to find tcp.csv on the same folder as scadufax binary
            with open('database/tcp.csv') as tcp_content:
                # read line by line
                for tcp_line in tcp_content:
                    # create port standard for compare
                    check_port = ',' + str(port_number) + ','
                    if check_port in tcp_line:
                        # if port found, extract services from line
                        checked_line = tcp_line.lower()
                        explode_line = checked_line.split('"',)
                        generated_service = explode_line[3]
                        # return service name
                        return generated_service
        except:
            try:
                # try to find tcp.csv on /usr/share scadufax (installed version)
                with open('/usr/share/scadufax/database/tcp.csv') as tcp_content:
                    # read line by line
                    for tcp_line in tcp_content:
                        # create port standard for compare
                        check_port = ',' + str(port_number) + ','
                        if check_port in tcp_line:
                            # if port found, extract services from line
                            checked_line = tcp_line.lower()
                            explode_line = checked_line.split('"',)
                            generated_service = explode_line[3]
                            # return service name
                            return generated_service
            except Exception as e:
                print (e)


    elif (protocol == 'udp'):
        try:
            # try to find tcp.csv on the same folder as scadufax binary
            with open('database/udp.csv') as udp_content:
                # read line by line
                for udp_line in udp_content:
                    # create port standard for compare
                    check_port = ',' + str(port_number) + ','
                    if check_port in udp_line:
                        # if port found, extract services from line
                        checked_line = udp_line.lower()
                        explode_line = checked_line.split('"',)
                        generated_service = explode_line[3]
                        # return service name
                        return generated_service
        except:
            try:
                # try to find tcp.csv on /usr/share scadufax (installed version)
                with open('/usr/share/scadufax/database/udp.csv') as udp_content:
                    # read line by line
                    for udp_line in tcp_content:
                        # create port standard for compare
                        check_port = ',' + str(port_number) + ','
                        if check_port in udp_line:
                            # if port found, extract services from line
                            checked_line = udp_line.lower()
                            explode_line = checked_line.split('"',)
                            generated_service = explode_line[3]
                            # return service name
                            return generated_service
            except Exception as e:
                print (e)


#-------------------------------------------------------------------------------------------------------------------------------------


# file output function
def output_logging(file_path, line_content):
    try:
        with open(file_path, 'a+') as write_line:
            write_line.write(line_content)
        write_line.close()
    except Exception as e:
        print (e)
