# Scadufax

A lightweight network scanner built with **Scapy** for host discovery and TCP reconnaissance.

Scadufax was originally developed in **2024** as a personal project to study packet crafting, TCP/IP networking and common port scanning techniques. The project focuses on simplicity, clean terminal output and educational value.

> **Project Status**
>
> This project is archived and is no longer under active development. It remains available for educational purposes and as a reference implementation built with Scapy.

---

# Features

- TCP port scanning
- ICMP host discovery
- SYN (Stealth) Scan
- NULL Scan
- FIN Scan
- XMAS Scan
- Single host scanning
- Network range scanning
- Custom port selection
- Configurable request interval
- Configurable timeout
- Custom source port
- Save scan results to file
- Display only open ports
- Colorized terminal output
- TCP/UDP service identification using CSV databases

---

# Project Structure

```text
.
├── data
│   ├── tcp.csv
│   └── udp.csv
├── modules
│   ├── iostream.py
│   └── network.py
├── README.md
├── requirements.txt
└── scadufax.py
```

Directory description:

| Directory | Description |
|------------|-------------|
| data | TCP and UDP service databases |
| modules | Internal project modules |
| scadufax.py | Main application entry point |

---

# Requirements

- Python 3.x
- Scapy
- Termcolor

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

# Usage

```bash
python3 scadufax.py [options]
```

## Command Line Options

| Option | Description |
|---------|-------------|
| `-h` | Show help message |
| `-t` | Perform TCP port scan |
| `-icmp` | ICMP host discovery *(requires root)* |
| `-s` | Scan type: SYN, NULL, FIN or XMAS *(requires root)* |
| `-d` | Target IP address |
| `-R` | Target IP range |
| `-p` | Ports to scan |
| `-i` | Delay between requests |
| `-timeout` | Response timeout |
| `-source-port` | Custom source port |
| `-o` | Save results to a file |
| `-open` | Display only open ports |

---

# Examples

## Scan a single host

```bash
scadufax -d 192.168.0.1 -p 21,22
```

---

## Scan multiple ports

```bash
python3 scadufax.py -R 192.168.0.1-192.168.0.254 -p 21,22,8
```

---

## Scan an IP range (SYN Scan)

```bash
sudo python3 scadufax.py -sS -R 192.168.0.1-192.168.0.254 -p 21,22,80,443
```

---

## ICMP Host Discovery

```bash
sudo python3 scadufax.py -icmp -R 192.168.0.1-192.168.0.254
```

---

# Scan Types

Scadufax implements several classic TCP scanning techniques.

| Type | Description |
|------|-------------|
| SYN | Half-open TCP scan |
| NULL | TCP packet with no flags set |
| FIN | TCP FIN scan |
| XMAS | TCP packet with FIN, PSH and URG flags |

Some scan types require root privileges because they rely on raw sockets.

---

# Service Database

Scadufax includes lightweight TCP and UDP service databases stored as CSV files.

Example:

```csv
"TCP",22,"SSH"
"TCP",80,"HTTP"
"TCP",443,"HTTPS"
```

During the scan, detected ports are matched against these databases to display human-readable service names.

---

# Output

Scadufax uses **Termcolor** to provide a clean and colorized terminal interface, making scan results easier to read.

---

# How It Works

Scadufax is built on top of **Scapy**, allowing packets to be crafted and analyzed directly in Python.

The scanner performs:

- Host discovery
- TCP packet generation
- Response analysis
- Service identification
- Terminal output formatting

without relying on external scanning tools.

---

# Limitations

- Designed primarily for IPv4 networks.
- Some scan types require root privileges.
- Service detection relies on the included CSV databases.
- Developed as an educational project and not intended to replace mature tools such as Nmap.

---

# License

This project is released under the MIT License.
