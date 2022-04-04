#!/usr/bin/env python3

import json
import requests
import ipaddress
from scapy.all import IP, PcapReader
from argparse import ArgumentParser

#company_keywords = ['cisco']
#company_keywords = ['amazon', 'aws', 'slack']
company_keywords = ['microsoft', 'azure', 'skype']


def process_pcap(pcap_file):
    IP.payload_guess = []
    #input_ip_list = set(p[IP].dst for p in PcapReader(pcap_file) if IP in p)
    ip_list1 = set(p[IP].dst for p in PcapReader(pcap_file) if IP in p and p[IP].src == "192.168.0.107")
    ip_list2 = set(p[IP].src for p in PcapReader(pcap_file) if IP in p and p[IP].dst == "192.168.0.107")
    input_ip_list = ip_list1 + ip_list2
    output_ip_list = []

    url = 'http://ip-api.com/json'
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
    print("IP list is", output_ip_list)


if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument("-f", "--file", help="Input CSV file")
    args = parser.parse_args()
    args_dict = vars(args)
    process_pcap(args_dict['file'])
