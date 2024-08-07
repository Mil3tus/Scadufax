\
Scadufax Network Scanner BETA

### options:
  **-h**, **--help**            show this help message and exit

  **-s** S,N,F or X         [**S**]tealth, [**N**]ull, [**F**]in, [**X**]mas **[root required]**
  
  **-t**                    default tcp sanner
  
  **-d** 192.168.0.1        single target
  
  **-R** X.X.X.1-X.X.X.254  range of targets
  
  **-p** 21 or 21,22,25     port number, range or default (top ports)
  
  **-i** 0.1-10             interval between each request
  
  **-o** scan_result.txt    output file
  
  **-source-port** 443      IDS/IPS/Firewall evasion
  
  **-timeout** 1-10         set request timeout
  
  **-open**                 show open ports only
  

  **EXAMPLES**

  ##### Simple syn scan and a target only
  ```
  scadufax -sS -d 192.168.0.1
  ```
  
  ##### Scan range of targets and specific port list
  ```
  scadufax -sS -R 192.168.0.1-192.168.0.254 -p 21,22,80,443
  ```

  ##### Scan tange of targets and specific ports (Firewall Evasion) and output file
  ```
  scadufax -sS -R 192.168.0.1-192.168.0.254 -source-port 443 -p 21,22,80 -o output_file.txt
  ```
  
  ##### Scan range of targets show only open ports
  ```
  scadufax -sS -R 192.168.0.1-192.168.0.254 -open
  ```
  
  ##### Scan target and specify a interval between requests (3 seconds)
   ``` 
  scadufax -sS -d 192.168.0.1 -i 3
   ```
  ##### Scan a range of targets (Null Scan)
   ``` 
  scadufax -sN -R 192.168.0.1-192.168.0.10 -p 21,22,53,3306
   ```

