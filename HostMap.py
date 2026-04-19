from scapy.all import ARP,Ether,srp
from rich.table import Table
from rich.console import Console
from mac_vendor_lookup import MacLookup
import argparse
import socket

'''
    HostMapper is Network scanning tool to find out what are the 
    machines are alive in the local network were you connected.
    You can only discover host information, notn port.
'''
class HostMapper:

    def __init__(self):
        self.args = self.argment()
        self.console = Console()  # console module is used for show the table in terminal
        self.table = Table(show_header=1,title=f"TARGET: {self.args.range}   INTERFACE: {self.args.interface}",header_style="bold yellow")
    
    def argment(self):
        parser = argparse.ArgumentParser(description="HostMap : Network Scanning Tool")
        parser.add_argument("-i","--interface",metavar="",help="Interface to scan the target",default=None)
        parser.add_argument("-r","--range",metavar="IP", help="Target IP address or Subnet range",default="192.168.1.0/24")
        parser.add_argument("-o","--output",metavar="",help="To save the scan result in files",default=None)

        return parser.parse_args()
    
    def scan(self,target,interface): 
        ''' First main thing is we need to find out mac address 
            of the target. To do that we send arp request to all the 
            ip of target network using boardcast address and receive 
            mac of the destination. '''
        
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        pkt = ether/arp # its a arp packet with boardcast address
        try:
            # send arp request and receive arp response with mac address
            responses = srp(pkt,iface=interface,timeout=2,verbose=False)[0] 
        except Exception as e:
            print(e)

        results = []
        for send,received in responses:
            ip = received.psrc
            mac = received.hwsrc
            pkt_len = len(send)
            results.append({"ip":ip,"mac":mac.lower(),"len":str(pkt_len)})
        return results
    
    def system_info(self,ip,mac):
        '''This function helps to find out vendor address and 
        host information about target '''
        try:
            vendor = MacLookup().lookup(mac) # vendor address lookup
        except LookupError:
            vendor = "Unknown"
        try:
            host = socket.gethostbyaddr(ip)[0] # host name using ip
        except socket.herror:
            host = "Unknown"
        return vendor,host

    def save(self,file,devices):
        with open(file,'a') as f:
            for device in devices:
                f.write(f'IP Address    : {device['ip']}\n')
                f.write(f'MAC Address   : {device['mac']}\n')
                f.write(f'Packet Length : {device['len']}\n')
                f.write(f'Vendor Address: {device['vendor']}\n')
                f.write(f'Host Name     : {device['host']}\n\n')
                
    def main(self):
        
        interface = self.args.interface 
        target = self.args.range
        output = self.args.output
        
        devices = self.scan(target,interface)

        for device in devices:
            vendor,host = self.system_info(device["ip"],device["mac"])
            device["vendor"] = vendor
            device["host"] = host

        # adding columns and its header
        self.table.add_column("IP ADDRESS",style="cyan")
        self.table.add_column("MAC ADDRESS",style="magenta")
        self.table.add_column("Len",style="white")
        self.table.add_column("MAC Vendor",style="green")
        self.table.add_column("Host Name",style="blue")

        for device in devices:
            # adding rows 
            self.table.add_row(device['ip'],device['mac'],device['len'],device['vendor'],device['host'])
        

        self.console.print(self.table) # this will print all the table we written

        if output:
            self.save(output,devices)

    
if __name__ == "__main__":
    netscan = HostMapper()
    netscan.main()
    


