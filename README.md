# BABYSHARK

Minimal, Simple and Fast packet sniffer in 🇨.

## Features
- Choose a specific interface: `babyshark -d <name>`  
- Limit the number of packages to capture: `babyshark -t <count>`  
- Use **libpcap** limit expressions: `babyshark -e <expressions>`   

## Usage
```bash
git clone https://github.com/0l3d/babyshark.git
cd babyshark/
make
./babyshark -h
Usage: babyshark [-h] [-d device/interface] [-t packet count] [-e expression]
```

## Expression Syntax
For more info on filter expression syntax, visit:  
`https://www.tcpdump.org/manpages/pcap-filter.7.html`  

## LICENSE
This project is licensed under the **GPL-3.0 License**.

## Author
Created by 0l3d.
