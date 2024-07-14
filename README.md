#### Scadufax Network Scanner
This is a network scanner based on Scapy created in Python 3.11.2

##### The Objective
This project was started only for improve skills and create a network scanner with a better output interface than that Nmap (of course, its almost impossible to create a scanner better than him in functions, but the focus is exclusive on the output interface)


**CAUTION:** This script can't be used with **proxychains** yet, because on **multiple target scan**, in order to improve the scanner speed, it sends a **icmp packet** to discover if host **is alive** or **not**, so soon this problem will be fixed!!

