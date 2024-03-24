#!/usr/bin/env python
"""
t2.py: Add great amount of records using PowerDNS API depending on couple of statements
        1. - the record in the zone *.univ.kiev.ua is looking at nuke
        2. - no record exists in the *.knu.ua zone.

        For each of the domains (example for mydomain), add two records to the knu.ua zone:
        1) mydomain CNAME nuke.knu.ua.
        2) www.mydomain CNAME mydomain.knu.ua.
"""
__author__ = "G3-IX"
__status__ = "Development"

import socket
import time
import sys
import os


def invoke_user_input():
    dns_for_check = input("Please set DNS Domain Name for check(if `None` 'nuke' will be used):")
    dns_zone_ckeck = input("Please set DNS Domain Name for check(if `None` '.univ.kiev.ua' will be used):")
    file_with_domains = input(
        "Please set file name from where to take the list of domains(if `None` 'notknu.txt' will be used):")
    is_debug_mode = input("Is debug mode - on?(N):")
    powerdns_domain_name = input("Please set powerdns server domain name(if `None` 'nuke' will be used):")
    powerdns_domain_zone = input("Please set powerdns server domain name(if `None` '.knu.ua' will be used):")
    key = input("Set powerDns key:")
    if key == '':
        key = 'changeMe'
    if dns_for_check == '':
        dns_for_check = 'nuke'
    if dns_zone_ckeck == '':
        dns_zone_ckeck = '.univ.kiev.ua'
    if file_with_domains == '':
        file_with_domains = 'notknu.txt'
    if is_debug_mode == 'Y' or is_debug_mode == 'y':
        is_debug_mode = True
    else:
        is_debug_mode = False
    if powerdns_domain_name == '':
        powerdns_domain_name = 'nuke'
    if powerdns_domain_zone == '':
        powerdns_domain_zone = '.knu.ua'
    lookupt1 = input(f"Use byCertainDomain as True for check in {dns_zone_ckeck} (`True`):")
    lookupt2 = input(f"Use byCertainDomain as True for check in {powerdns_domain_zone} (`False`):")
    if lookupt1 == '':
        lookupt1 = True
    else:
        lookupt1 = False
    if lookupt2 == '':
        lookupt2 = False
    else:
        lookupt2 = True
    print('Proceeding..')
    print('This may take some time..')
    print('....')
    return dns_for_check, dns_zone_ckeck, file_with_domains, is_debug_mode, powerdns_domain_name, powerdns_domain_zone, lookupt1, lookupt2, key


def check_dns_resolution_dns(domain, dns_for_check="nuke.univ.kiev.ua"):  #
    DNS = 'NONE'
    ip = "NONE EXISTENT OR LOCAL DNS"
    try:
        ip_address = socket.gethostbyname(domain)
        try:
            dns = socket.gethostbyaddr(ip_address)
            return dns[0].endswith(dns_for_check), dns[0], ip_address
        except:
            # print(f"err on {domain} with ip {ip_address}" )
            return False, "VARIABLE", ip_address

    except socket.gaierror:
        return False, DNS, ip


def check(dnsDomain='.univ.kiev.ua', dnsName='nuke', domain_list=['google'], byCertainDomain=False, show_all=False, ):
    try:
        nonexistent_or_local_domains = []
        other_dns = []
        nuke_dns_or_univ_dns = []
        for domain in domain_list:
            domain = domain.strip()
            domain = domain + dnsDomain
            if byCertainDomain:
                dns_for_test = dnsName + dnsDomain
                univ_dns, dns_server, dns_ip = check_dns_resolution_dns(domain, dns_for_check=dns_for_test)
            else:
                univ_dns, dns_server, dns_ip = check_dns_resolution_dns(domain, dns_for_check=dnsDomain)
            if univ_dns:
                if show_all: print(f" {domain} - Resolves with .nuke.kiev.ua DNS server: {dns_server}")
                nuke_dns_or_univ_dns.append(domain)
            else:
                if show_all: print(f' {domain} - Resolves with non-listed DNS server -@- {dns_server} (IP: {dns_ip})')
                if dns_server == 'NONE':
                    nonexistent_or_local_domains.append(domain)
                else:
                    other_dns.append(domain)
            if show_all: print("-" * 40)
        if byCertainDomain:
            fill = dnsName

        else:
            fill = '*'
        print(f"Looks up on {fill + dnsDomain}", nuke_dns_or_univ_dns)
        print(f"\nDo not looks up on {fill + dnsDomain}", other_dns)
        print(f"\nNonexistent", nonexistent_or_local_domains)
        print('---------------------')
        return nuke_dns_or_univ_dns, other_dns, nonexistent_or_local_domains
    except Exception as error:
        print('check error: ', error)


def DNS_update(list_of_domains, dns_server_name, dns_server_zone, is_nsupdate=False, DNS_ttl=86400,
               dns_server_ip="192.168.1.1", X_API_Key='changeMe', api_data='localhost', port=8081, fwd_to='knu.ua', fwd_d_name = 'univ' + '.'):
    # DNS_ttl = 86400  # sec = 1day
    commands = ''
    if is_nsupdate:
        commands += "nsupdate\n"
        for domain in list_of_domains:
            temp = domain + dns_server_zone
            commands += f"prereq nxdomain {temp}\nupdate add {temp} {DNS_ttl} A {dns_server_ip}\n"
        print(commands)
        proceed = input('Now following commands will be executed in os, proceed?(N):')
        if proceed == 'Y' or proceed == 'y':
            os.system(commands)
        else:
            print('Aborted..')
    else:
        from datetime import datetime
        now = datetime.now()
        current_time = now.strftime("%Y%m%d%H")
        comment = input('Print in comment (if `None` default statement will be used):')  # Created by script from Venax
        if comment == '':
            comment = 'Created by script from Venax'
        for domain in list_of_domains:
            temp = domain + '.' + dns_server_zone
            api = f'{api_data}:{port}/api/v1/servers/localhost/zones/{dns_server_zone}.'
            records_payload = '[{"content":"' + fwd_d_name + fwd_to + '.","set_ptr":false,"disabled":false}]'
            comment_payload = '"comments":[{ "account": "", "content": "' + comment + '", "modified_at": ' + f'{current_time}' + '}],'
            data = '{"rrsets":[{' + comment_payload + '"name":"' + temp + '.' + '","type":"CNAME","ttl":3600,"changetype":"REPLACE","records":' + records_payload + '}]}'
            wwwdata = '{"rrsets":[{' + comment_payload + '"name":"' + 'www.' + temp + '.' + '","type":"CNAME","ttl":3600,"changetype":"REPLACE","records":' + records_payload + '}]}'
            commands += f"curl -s -H 'X-API-Key: {X_API_Key}' -X PATCH -d '{data}' {api}\n"
            commands += f"curl -s -H 'X-API-Key: {X_API_Key}' -X PATCH -d '{wwwdata}' {api}\n"
        print(commands)
        proceed = input('Now following commands will be executed in os, proceed?(N):')
        if proceed == 'Y' or proceed == 'y':
            os.system(commands)
        else:
            print('Aborted..')


def Main():
    dns_for_check, dns_zone_ckeck, file_with_domains, is_debug_mode, powerdns_domain_name, powerdns_domain_zone, lookupt1, lookupt2, X_API_Key = invoke_user_input()
    domainsTotal = []
    with open(file_with_domains, "r") as f:
        for url in f:
            url = url.strip()
            if 'www' in url:
                domainsTotal.append(url[4:])
            else:
                domainsTotal.append(url)
    domainsTotal.sort()
    no_dup = list(set(domainsTotal))
    no_dup.sort()
    domainsOnly = []
    for i in no_dup:
        take_domain = len(dns_zone_ckeck)
        domainsOnly.append(i[:-take_domain])
        # print(i ,'----', i[:-take_domain])

    nukeUniv_exist, nukeUniv_other, nukeUniv_none = check(dnsDomain=dns_zone_ckeck, dnsName=dns_for_check,
                                                          domain_list=domainsOnly,
                                                          show_all=is_debug_mode, byCertainDomain=lookupt1)
    nukeKnu_exist, nukeKnu_other, nukeKnu_none = check(dnsDomain=powerdns_domain_zone, dnsName=powerdns_domain_name,
                                                       domain_list=domainsOnly,
                                                       show_all=is_debug_mode, byCertainDomain=lookupt2)

    # print('<<<<<--------------->>>>>')

    for UnivDomainExitID in range(len(nukeUniv_exist)):
        # nukeUniv_exist[UnivDomainExitID] = nukeUniv_exist[UnivDomainExitID].replace(".univ.kiev.ua", "")
        nukeUniv_exist[UnivDomainExitID] = nukeUniv_exist[UnivDomainExitID].replace(dns_zone_ckeck, "")
    for KnuDomainNonexistentID in range(len(nukeKnu_none)):
        nukeKnu_none[KnuDomainNonexistentID] = nukeKnu_none[KnuDomainNonexistentID].replace(powerdns_domain_zone, "")

    result = list(set(nukeUniv_exist) & set(nukeKnu_none))
    result.sort()
    print(f'Such domains are True for statement the record in the zone *{dns_zone_ckeck} is looking at {dns_for_check}')
    print(f'and NO record exists in the *{powerdns_domain_zone} zone.')
    print(result)
    DNS_update(result, powerdns_domain_name, powerdns_domain_zone[1:], is_nsupdate=False,
               dns_server_ip='91.202.128.71', X_API_Key=X_API_Key, fwd_to=powerdns_domain_zone, fwd_d_name=powerdns_domain_name)  # dns_server_ip = debug option


Main()
