#!/usr/bin/env python3
# -*- coding:utf-8 -*-
'''
by arm1ng
Use TCP ACK to scan which port is unfilter and open.
'''
import sys
from scapy.all import IP, TCP, sr, fuzz


def help():
    '''
host_ip port

  port:
        --all		全端口扫描
        --default	默认端口扫描
        <port_num>	指定端口扫描 eg:21,23,24	
        '''


def ack(ip, port):
    # 发送ACK包判断端口是否被过滤
    int_port = list(map(int, port.split(",")))
    # 将输入的端口字符型列表变为整数型列表
    print(ip, int_port)
    ans, unans = sr(IP(dst=ip) / TCP(dport=int_port, flags="A"))
    return ans, unans


def syn(ip, port):
    # 发送SYN包判断端口是否开放
    ans, unans = sr(IP(dst=ip) / fuzz(TCP(dport=port, flags="S")))
    return ans, unans


if sys.argv[1] == '--help':
    print(help.__doc__)
    exit()

elif sys.argv[2] == '--default':
    default_port = '21,22,23,25,53,69,80,81,82,83,84,85,86,87,88,89,110,135,139,143,443,445,465,993,995,1080,1158,' \
                   '1433,1521,1863,2049,2100,3128,3306,3389,7001,8080,8081,8082,8083,8084,8085,8086,8087,8888,9080,' \
                   '9090 '
    ans, unans = ack(sys.argv[1], default_port)
elif sys.argv[2] == '--all':
    all_port = []
    for i in range(1, 65536):
        all_port.append(str(i))
    all_port = ','.join(all_port)
    print(all_port)
    ans, unans = ack(sys.argv[1], all_port)
else:
    ans, unans = ack(sys.argv[1], sys.argv[2])

# print(ans,unans)
P = []
F = []
for s, r in ans:
    # 读取对ACK有回应的源端与远端通信包
    if s[TCP].dport == r[TCP].sport:
        ans, unans = syn(sys.argv[1], s[TCP].dport)
        # 执行SYN扫描
        for s, r in ans:
            # 读取对SYN有回应的源端与远端通信包
            if r[TCP].flags == 18:
                # 远端回应包flags为0x012(SYN,ACK)
                print("[+]The port " + str(r[TCP].sport) + " is unfiltered and open")
                P.append(r[TCP].sport)
                # print(P)
            if r[TCP].flags == 20:
                # 远端回应包flags为0x014(RST,ACK)
                print("[-]The port " + str(r[TCP].sport) + " is unfiltered and closed")

for s in unans:
    # 读取对ACK无回应的源端通信包
    print("[!]The port " + str(s[TCP].dport) + " is filtered")
    F.append(s[TCP].dport)
    # print(F)

print()
print("=" * 30)
for open_port in P:
    print("[+]The port " + str(open_port) + " is unfiltered and open")
for filter_port in F:
    print("[!]The port " + str(filter_port) + " is filtered")
