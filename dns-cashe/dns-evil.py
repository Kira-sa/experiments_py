""" 
TODO: Написать кеширующий DNS-сервер, 
 * отвечающий на корректные запросы по протоколу DNS (RFC 1035) корректными ответами, 
 * данные сервер должен брать из своего кэша или (в случае устаревания или отсутствия данных в кэше) переспрашивать у указанного сервера (см. BIND forwarders).

[1-7]   реализация кэша на основе query records в качестве ключа.

[8-15]  парсинг пакета для помещения в кэш записей из секций AN, NS, AR 
        (в серии запросов dig mail.ru mx; dig mxs.mail.ru второй ответ - из кеша). 
        Самостоятельная сборка пакета с ответом.

[16-20] обработка зацикливания (корректное поведение сервера в случае, если в 
        качестве «старшего сервера» указан он же сам, или экземпляр его, запущенный на другой машине)

Обязательно должно быть реализовано
* устаревание данных в кэше (обработка TTL), при этом клиентам должны отдавать 
    актуальное значение ttl, то есть если 10 секунд назад от форвардера получили 
    ответ, что данные устареют через 700 секунд, то клиенту говорим, что ttl для 
    имеющейся у нас в кэше записи равен 690
* временный отказ вышестоящего сервера (сервер не должен терять работоспособность 
    (уходить в бесконечное ожидание, падать с ошибкой и т.д.), если старший 
    сервер почему-то не ответил на запрос к нему)
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
import binascii

dns = (('8.8.8.8',53), )


def parse_args():
    """ Проверка входных аргументов """
    parser = argparse.ArgumentParser(description='dns-cache py app')
    parser.add_argument('-p', '--port', type=int, default=53,  help='Прослушиваемый порт')
    parser.add_argument('-f', '--forwarder', type=str,  default=['8.8.8.8:53'],  help='ip-адрес или символьное имя форвардера, c портом или без')

    return parser.parse_args().__dict__


def start(port: int, forwarder:str):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('localhost', port))
    s.settimeout(1)

    sntp = DNSServer(s, forwarder)
    sntp.run()


class Cache():
    def __init__(self,filename=':memory:') -> None:
        self.db = sqlite3.connect(filename, isolation_level=None)
        self.db.text_factory = str
        cursor = self.db.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS T_CACHE (K BLOB PRIMARY KEY,V BLOB)')
        cursor.execute('PRAGMA journal_mode = off')
        cursor.close()
        pass

    def get(self):
        cursor = self.db.cursor()
        return None
    
    def put(self, K, V):
        cursor = self.db.cursor()
        pass

class DNSServer:
    """ 
    * слушать порт
    * получив запрос проверить кэш - если в нём есть инфо - ответить по запросу,
        если нет - спросить у старшего, сохранить ответ, ответить по запросу
    * многопоточность (1 слушать, 1 отвечать)
    * если указанный старший не ответил, проверить у дефолтного или сообщить об ошибке

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
                # if self.task.empty():
                    # time.sleep(1)
                req, req_addr, req_time = self.task.get(timeout=1)
                request = DNSpack()
                # request.parse_package(req)  # разбираем запрос клиента
                response = self.prepare_response(request, req_time).create_package() # готовим ответ
                self.sock.sendto(response, req_addr)  # отправляем
            except queue.Empty:
                continue
    
    def prepare_response(self):
        pass

    def parse_request(self):
        pass


class DNSpack():
    def __init__(self) -> None:
        pass

    def build_packet(self, url):
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

    def parse_packet(self, pack):
        id = 0
        flags = 0
        QDCOUNT = 0
        ANCOUNT = 0
        NSCOUNT = 0
        ARCOUNT = 0
        
        return ()


if __name__ == "__main__":
    try:
        args = parse_args()
        start(**args)

    except KeyboardInterrupt:
        print('\nTerminated.')
        exit()