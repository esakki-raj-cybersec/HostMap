# HostMap

HostMap is a Python-based network discovery and ARP mapping tool.  
It leverages **Scapy** for packet crafting, **Rich** for styled console output, and **Mac Vendor Lookup** for resolving device vendors from MAC addresses.

---

## 🚀 Features
- Discover hosts on a local network using ARP requests.
- Display results in a styled table with **Rich**.
- Identify device vendors via MAC address lookup.
- Simple CLI interface with **argparse**.
- Lightweight and easy to run on Kali Linux or any Python environment.

---

## 📦 Installation and Usage

Clone the repository:
```bash
git clone git@github.com:esakki-raj-cybersec/HostMap.git
cd HostMap
```

Install dependencies with:
```bash
pip install -r requirements.txt
```
Usage:
```bash
python3 HostMap.py -r 192.168.1.0/24 -i eth0
```
Save the scan result:
```bash
python3 HostMap.py -r 192.168.1.0/24 -i eth0 -o scan.txt
```
Help:
```bash
python3 HostMap.py -h
```

## 📊 Example Output:
