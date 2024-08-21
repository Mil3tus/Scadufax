Scadufax is a network scanner based on Scapy libraries.
Per now, i am working on TCP protocol functions, after this stage
i pretend to implement UDP protocol support.

**IMPORTANT:** SYN/XMAS/NULL/FIN Scan doesn't work with *proxychains* tool, and require
root mode to work.

**Requires Libraries**

* argparse
* sys
* time
* random
* scapy
* socket
* logging
* termcolor

**Compiling Code with Pyinstaller**

```
pyinstaller -D -F -n scadufax -c scadufax.py -paths=/lib/python3/dist-packages --paths=include --onefile
```

***

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

