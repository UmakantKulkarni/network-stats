#!/usr/bin/env python3

import os
import json
import requests
import ipaddress
from scapy.all import IP, PcapReader, UDP
from argparse import ArgumentParser

company_dict = {"webex": ['cisco', 'webex'], "slack": ['amazon', 'aws', 'slack'], "teams": ['microsoft', 'azure'], "skype": ['microsoft', 'azure', 'skype'], "zoom": ['amazon', 'aws', 'zoom', 'akamai'], "discord": ['Cloudflare', 'i3d', 'discord'], "google": ['google'], "hulu": ['i3d', 'level3', 'hulu']}
my_ip = "192.168.0.107"


def append_ip_tolist(ip_lst, ip_addr):
    if not ipaddress.ip_address(ip_addr).is_private:
        if ip_addr not in ip_lst:
            ip_lst.append(ip_addr)


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
        for pkt in PcapReader(pcap_file):
            if UDP in pkt:
                if pkt[UDP].sport == 500 and pkt[UDP].dport == 500:
                    append_ip_tolist(output_ip_list, pkt[IP].src)
                    append_ip_tolist(output_ip_list, pkt[IP].dst)
                elif pkt[UDP].sport == 4500 and pkt[UDP].dport == 4500:
                    append_ip_tolist(output_ip_list, pkt[IP].src)
                    append_ip_tolist(output_ip_list, pkt[IP].dst)

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
