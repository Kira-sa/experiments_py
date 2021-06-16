"""  TODO: Написать кеширующий DNS-сервер,
 * отвечающий на корректные запросы по протоколу DNS (RFC 1035)
    корректными ответами,
 * данные сервер должен брать из своего кэша или (в случае устаревания или
    отсутствия данных в кэше) переспрашивать у указанного сервера
    (см. BIND forwarders).

[1-7]   реализация кэша на основе query records в качестве ключа.

[8-15]  парсинг пакета для помещения в кэш записей из секций AN, NS, AR
        (в серии запросов dig mail.ru mx; dig mxs.mail.ru второй ответ
        - из кеша). Самостоятельная сборка пакета с ответом.

[16-20] обработка зацикливания (корректное поведение сервера в случае, если в
        качестве «старшего сервера» указан он же сам, или экземпляр его,
        запущенный на другой машине)

Обязательно должно быть реализовано
* устаревание данных в кэше (обработка TTL), при этом клиентам должны отдавать
    актуальное значение ttl, то есть если 10 секунд назад от форвардера
    получили ответ, что данные устареют через 700 секунд, то клиенту говорим,
    что ttl для имеющейся у нас в кэше записи равен 690
* временный отказ вышестоящего сервера (сервер не должен терять
    работоспособность (уходить в бесконечное ожидание, падать с ошибкой
    и т.д.), если старший сервер почему-то не ответил на запрос к нему)
"""

import argparse
import threading
import socket
import queue
import time
import select
import sqlite3
import random
import struct


dns = (('8.8.8.8', 53), )


def parse_args():
    """ Проверка входных аргументов """
    parser = argparse.ArgumentParser(description='dns-cache py app')
    parser.add_argument(
        '-p', '--port',
        type=int, default=53,
        help='Прослушиваемый порт')
    parser.add_argument(
        '-f', '--forwarder',
        type=str, default=['8.8.8.8:53'],
        help='ip-адрес или символьное имя форвардера, c портом или без'
        )

    return parser.parse_args().__dict__


def start(port: int, forwarder: str):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('localhost', port))
    s.settimeout(1)

    sntp = DNSServer(s, forwarder)
    sntp.run()


class Cache():
    def __init__(self, filename=':memory:') -> None:
        self.db = sqlite3.connect(filename, isolation_level=None)
        self.db.text_factory = str
        cursor = self.db.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS T_CACHE \
            (K BLOB PRIMARY KEY,V BLOB)')
        cursor.execute('PRAGMA journal_mode = off')
        cursor.close()
        pass

    def get(self):
        cursor = self.db.cursor()
        a = cursor
        a += a
        return None

    def put(self, K, V):
        cursor = self.db.cursor()
        a = cursor
        a += a
        pass


class DNSServer:
    """
    * слушать порт
    * получив запрос проверить кэш - если в нём есть инфо - ответить
        по запросу, если нет - спросить у старшего, сохранить ответ,
        ответить по запросу
    * многопоточность (1 слушать, 1 отвечать)
    * если указанный старший не ответил, проверить у дефолтного или
        сообщить об ошибке
    """
    def __init__(self, s, forwarder) -> None:
        self.s = s
        self.forwarder = forwarder
        self.task = queue.Queue()

    def run(self):
        print("DNS server start")
        receiver = threading.Thread(target=self.listen)
        receiver.start()
        sender = threading.Thread(target=self.response)
        sender.start()

    def listen(self):
        while True:
            timeout = 3
            ready_to_read, _, _ = select.select([self.sock], [], [], timeout)
            if ready_to_read:
                self.add_task(ready_to_read)

    def add_task(self, ready_to_read):
        for client in ready_to_read:
            request, addr = client.recvfrom(1024)
            print("Connected: {}".format(addr[0]))
            self.task.put((request, addr, time.time()))

    def response(self):
        while True:
            try:
                req, req_addr, req_time = self.task.get(timeout=1)
                request = decode_dns_message(req)
                # request.parse_package(req)  # разбираем запрос клиента
                response = self.prepare_response(
                    request, req_time).create_package()  # готовим ответ
                self.sock.sendto(response, req_addr)  # отправляем
            except queue.Empty:
                continue

    def prepare_response(self):
        pass

    def parse_request(self):
        pass


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
    packet += struct.pack(">H", 1)  # QDCOUNT  Number of questions         4bit
    packet += struct.pack(">H", 0)  # ANCOUNT  Number of answers           4bit
    packet += struct.pack(">H", 0)  # NSCOUNT  Number of authority records 4bit
    packet += struct.pack(">H", 0)  # ARCOUNT  Number of additional records4bit
    split_url = url.split(".")
    for part in split_url:
        packet += struct.pack("B", len(part))
        for s in part:
            packet += struct.pack('c', s.encode())
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
    id, raw_flags, qdcount, ancount, ns, ar = struct.unpack("!6H", message)
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
              "answer_count": ancount,
              "authority_count": ns,
              "additional_count": ar,
              "questions": questions}

    return result


if __name__ == "__main__":
    try:
        args = parse_args()
        start(**args)

    except KeyboardInterrupt:
        print('\nTerminated.')
        exit()
