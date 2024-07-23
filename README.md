### Scadufax Commands

usage: scadufax.py [-h] [-s S,N,F or X] [-t] [-d 192.168.0.1] [-R X.X.X.1-X.X.X.254]\
                   [-p 21 or 21,22,25] [-i 0.1-10] [-o scan_result.txt] [-source-port 443]\
                   [-timeout 1-10] [-open]\
\
Scadufax Network Scanner

options:\
  -h, --help            show this help message and exit\
  -s S,N,F or X         [S]tealth, [N]ull, [F]in, [X]mas [root required]\
  -t                    default tcp sanner\
  -d 192.168.0.1        single target\
  -R X.X.X.1-X.X.X.254  range of targets\
  -p 21 or 21,22,25     port number, range or default (top ports)\
  -i 0.1-10             interval between each request\
  -o scan_result.txt    output file\
  -source-port 443      IDS/IPS/Firewall evasion\
  -timeout 1-10         set request timeout\
  -open                 show open ports only\

