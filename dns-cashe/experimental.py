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



def encode_dns_message(url):
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

def decode_labels(message, offset):
    labels = []

    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2

            return labels + decode_labels(message, pointer & 0x3FFF), offset

        if (length & 0xC0) != 0x00:
            # raise StandardError("unknown label encoding")
            print("unknown label encoding")
            return

        offset += 1
        if length == 0:
            return labels, offset
        labels.append(*struct.unpack_from("!%ds" % length, message, offset))
        offset += length

def decode_question_section(message, offset, qdcount):
    questions = []
    for _ in range(qdcount):
        qname, offset = decode_labels(message, offset)
        qtype, qclass = struct.unpack_from("!2H", message, offset)
        offset += struct.calcsize("!2H")
        question = {"domain_name": qname,
                    "query_type": qtype,
                    "query_class": qclass}
        questions.append(question)

    return questions, offset

def parse_flags(flags):
    res = {}
    res['qr'] = (flags & 0x8000) != 0
    res['opcode'] = (flags & 0x7800) >> 11
    res['aa'] = (flags & 0x0400) != 0
    res['tc'] = (flags & 0x200) != 0
    res['rd'] = (flags & 0x100) != 0
    res['ra'] = (flags & 0x80) != 0
    res['z'] = (flags & 0x70) >> 4
    res['rcode'] = flags & 0xF
    return res

def decode_dns_message(message):
    id, raw_flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", message[:12])
    flags = parse_flags(raw_flags)
    offset = struct.calcsize("!6H")
    questions, offset = decode_question_section(message, offset, qdcount)

    result = {"id": id,
              "is_response": flags['qr'],
              "opcode": flags['opcode'],
              "is_authoritative": flags['aa'],
              "is_truncated": flags['tc'],
              "recursion_desired": flags['rd'],
              "recursion_available": flags['ra'],
              "reserved": flags['z'],
              "response_code": flags['rcode'],
              "question_count": qdcount,
              "AN": ancount,  # AN  answer_count
              "NS": nscount,  # NS  authority_count
              "AR": arcount,  # AR  additional_count
              "questions": questions}

    return result




def experimental():
    request = encode_dns_message("ya.ru")
    print(request)
    for s in dns:
        sk = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sk.settimeout(5)
        sk.connect(s)
        # try:
        sk.send(request)
        raw_response, addr = sk.recvfrom(2048)
        print(raw_response)
        resp = decode_dns_message(raw_response)
        print(resp)
        a = 34
        # except Exception as e:
        #     response = None
        # finally:
        #     sk.close()
        if raw_response:
            # self.dns_cache.put(K,response[4:])
            a = 23

            return raw_response[2:]


experimental()