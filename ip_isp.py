#!/usr/bin/env python3

import os
import json
import requests
import ipaddress
from scapy.all import IP, PcapReader
import pcapy
import impacket
from impacket import ImpactDecoder
from impacket.ImpactPacket import UDP
from argparse import ArgumentParser

company_dict = {"webex": ['cisco', 'webex'], "slack": ['amazon', 'aws', 'slack'], "teams": ['microsoft', 'azure'], "skype": ['microsoft', 'azure', 'skype'], "zoom": ['amazon', 'aws', 'zoom', 'akamai'], "discord": ['cloudflare', 'i3d', 'discord'], "google": ['google'], "hulu": ['i3d', 'level', 'hulu', 'akamai'], "hbo": ['limelight', 'akamai'], "peacock": ['akamai'], "prime": ['amazon', 'aws']}
my_ip = "192.168.0.107"


def append_ip_tolist(ip_lst, ip_addr):
    if not ipaddress.ip_address(ip_addr).is_private:
        if ip_addr not in ip_lst:
            ip_lst.append(ip_addr)
    return ip_lst


def process_pcap(pcap_file, addnl_ip_list=[]):
    IP.payload_guess = []
    output_ip_list = []
    pcap_base_name = os.path.basename(pcap_file)
    if "vpn" not in pcap_base_name:
        for key in company_dict:
            if pcap_base_name[0:4] == key[0:4]:
                company_keywords = company_dict[key]
        if pcap_base_name[0:4] == "skyp":
            addnl_ip_list.append("172.56.12.45")
        else:
            addnl_ip_list = []

        #input_ip_list = set(p[IP].dst for p in PcapReader(pcap_file) if IP in p)
        ip_list1 = set(p[IP].dst for p in PcapReader(
            pcap_file) if IP in p and p[IP].src == my_ip)
        ip_list2 = set(p[IP].src for p in PcapReader(
            pcap_file) if IP in p and p[IP].dst == my_ip)
        input_ip_list = list(set(list(ip_list1) + list(ip_list2)))

        #url = 'http://ip-api.com/json'
        url = 'https://pro.ip-api.com/json'
        for ip in input_ip_list:
            if not ipaddress.ip_address(ip).is_private:
                rsp = requests.get(url="{}/{}".format(url, ip))
                try:
                    output = json.loads(rsp.content)
                except:
                    continue
                output = json.loads(rsp.content)
                for company in company_keywords:
                    isp = output.get('isp')
                    org = output.get('org')
                    asp = output.get('as')
                    if (isp != None and company in isp.lower()) or (org != None and company in org.lower()) or (asp != None and company in asp.lower()):
                        print(output)
                        output_ip_list.append(ip)
    else:
        pktreader = pcapy.open_offline(pcap_file)
        decoder = ImpactDecoder.EthDecoder()

        while 1:
            (pktheader, pktdata) = pktreader.next()
            if pktheader is None:
                break

            try:
                frame = decoder.decode(pktdata)
                packet = frame.child()
            except:
                continue

            src = None
            dst = None
            isAnyIP = False
            if isinstance(packet, impacket.ImpactPacket.IP):
                src = packet.get_ip_src()
                dst = packet.get_ip_dst()
                isAnyIP = True
            if(isAnyIP):
                segment = packet.child()
                sport = 0
                dport = 0
                if isinstance(segment, UDP):
                    sport = segment.get_uh_sport()
                    dport = segment.get_uh_dport()
                    if sport == 500 and dport == 500:
                        output_ip_list = append_ip_tolist(output_ip_list, src)
                        output_ip_list = append_ip_tolist(output_ip_list, dst)
                    elif sport == 4500 and dport == 4500:
                        output_ip_list = append_ip_tolist(output_ip_list, src)
                        output_ip_list = append_ip_tolist(output_ip_list, dst)

    rtrn_list = list(set(output_ip_list)) + addnl_ip_list
    print("")
    print("IP list for PCAP file {} is ".format(pcap_file), rtrn_list)
    print("")
    return rtrn_list


if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument("-f", "--file", help="Input CSV file")
    args = parser.parse_args()
    args_dict = vars(args)
    process_pcap(args_dict['file'])
