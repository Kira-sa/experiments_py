import argparse
import threading
import socket
import queue
import time
import select
import sqlite3
import binascii
import struct
import random


dns = (('8.8.8.8',53), ('8.8.4.4',53), )


def build_packet(url):
    # Flags
    # QR = 0      # Query: 0, Response: 1     1bit
    # OPCODE = 0  # Standard query            4bit
    # AA = 0      # ?                         1bit
    # TC = 0      # Message is truncated?     1bit
    # RD = 1      # Recursion?                1bit
    # RA = 0      # ?                         1bit
    # Z = 0       # ?                         3bit
    # RCODE = 0   # ?                         4bit
    randint = random.randint(0, 65535)
    packet = struct.pack(">H", randint)  # Query Ids # Query: 0, Response: 1 
    packet += struct.pack(">H", 0x0100)  # Flags
    packet += struct.pack(">H", 1)  # QDCOUNT  Number of questions           4bit
    packet += struct.pack(">H", 0)  # ANCOUNT  Number of answers             4bit
    packet += struct.pack(">H", 0)  # NSCOUNT  Number of authority records   4bit
    packet += struct.pack(">H", 0)  # ARCOUNT  Number of additional records  4bit
    split_url = url.split(".")
    for part in split_url:
        packet += struct.pack("B", len(part))
        for s in part:
            packet += struct.pack('c',s.encode())
    packet += struct.pack("B", 0)   # Terminating bit for QNAME
    packet += struct.pack(">H", 1)  # QTYPE Query Type
    packet += struct.pack(">H", 1)  # QCLASS Query Class
    return packet




def experimental():
    request = build_packet("ya.ru")
    print(request)
    # request = bytes(request_raw, 'utf-8')
    # print(request)
    a = 23
    for s in dns:
        sk = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sk.settimeout(5)
        sk.connect(s)
        # try:
        sk.send(request)
        response, addr = sk.recvfrom(2048)
        print(response)
        a = 34
        # except Exception as e:
        #     response = None
        # finally:
        #     sk.close()
        if response:
            # self.dns_cache.put(K,response[4:])
            a = 23

            return response[2:]


experimental()