# Scadufax Network Scanner
This is a network scanner based on Scapy created in Python 3.11.2

## The Objective
This project was started only for study proposes.

***

## Required Libraries
* termcolor
* time
* datetime
* socket
* logging
* scapy
* _thread
* random
* os
* argparse

## Help Menu

options:
  -h, --help            show this help message and exit
  -s                    scan tcp/syn mode [no Proxychains / Sudo required]
  -t                    three way handshake scan mode
  -d 192.168.0.1        single target
  -R X.X.X.1-X.X.X.254  range of targets
  -p 21 or 21,22,25     port number, range or default (top ports)
  --source-port 443     IDS/IPS/Firewall evasion
  --timeout 1-10        set request timeout
  --script <script>     --script help for list
  -i 0.1-10             interval between each request
  --open                show only open ports
  -o scan_result.txt    output file

