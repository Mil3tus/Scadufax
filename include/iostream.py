# iostream module
# created by H1d0raKai

# required libraries
from termcolor import colored
import time
import datetime

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


# scadufax scanner banner
def scadufax_banner():
    time.sleep(1)
    print ('\n\t\t', end='')
    print (colored('->', 'green', attrs=['bold']), end='')
    print (' Scadufax Network Scanner ', end='')
    print (colored('<-', 'green', attrs=['bold']))
    print ('\t\t     created by mr.n1k0v')
    print ('\t\t    Grumpsoft Corporation\n')


# show scadufax profile scanning
def load_scadufax_profile(target_address, source_port, destination_port, request_timeout):
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
    print ('] destination port(s): ' + str(destination_port))
    print ('\t[', end='')
    print (colored('>', 'cyan', attrs=['bold']), end='')
    print ('] request timeout: ' + str(request_timeout))

# time left message
def time_left_message(time_value):
    print ('\n[', end='')
    print (colored('+', 'red', attrs=['bold']), end='')
    print ('] estimated task time [ ' + str(time_value) + ' ]')

# start scanning message
def start_scanning_message():
    time.sleep(1)
    print ('[', end='')
    print (colored('*', 'green', attrs=['bold']), end='')
    print ('] start scanning [' + str(datetime.datetime.now()) + ']')

# start scanning message
def finish_scanning_message():
    time.sleep(1)
    print ('[', end='')
    print (colored('*', 'light_cyan', attrs=['bold']), end='')
    print ('] task finished [' + str(datetime.datetime.now()) + ']\n')


# show target address on screen
def printf_target(target_address):
    print ('\n[', end='')
    print (colored('!', 'yellow', attrs=['bold']), end='')
    print ('] ' + str(target_address))


# show open port message
def printf_open(port_address, port_service):
    print ('\t', end='')
    print (colored('-', 'white', attrs=['bold']), end='')
    print (' ' + str(port_address) + '/tcp\t', end='')
    print (colored('open', 'green'), end='')
    print ('\t' + str(port_service))

# show filtered port message
def printf_filtered(port_address, port_service):
    print ('\t', end='')
    print (colored('-', 'white', attrs=['bold']), end='')
    print (' ' + str(port_address) + '/tcp\t', end='')
    print (colored('filter', 'yellow'), end='')
    print ('\t' + str(port_service))

# show close port message
def printf_closed(port_address, port_service):
    print ('\t', end='')
    print (colored('-', 'white', attrs=['bold']), end='')
    print (' ' + str(port_address) + '/tcp\t', end='')
    print (colored('closed', 'red'), end='')
    print ('\t' + str(port_service))

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
