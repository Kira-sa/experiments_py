

""" 
TODO:
* Написать сканер TCP- и UDP-портов удалённого компьютера.
Вход: адрес хоста и диапазон портов
( ) 1 список открытых TCP-портов,
( ) 2 список открытых UDP-портов,
( ) 3 многопоточность,
( ) 4 распознать прикладной протокол по сигнатуре (NTP/DNS/SMTP/POP3/IMAP/HTTP).

-t - сканировать tcp
-u - сканировать udp
-p N1 N2, --ports N1 N2 - диапазон портов

Вывод:
В одной строке информация об одном открытом порте (через пробел):
TCP 80 HTTP
UDP 128
UDP 123 SNTP

Если протокол не определен - сообщить об ошибке

"""


import argparse  # для разбора аргументов
import sys
import socket
# from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM, socket, timeout
import threading 
from datetime import datetime, time
from traceback import print_exc
import re
from typing import List, Tuple
from threading import Lock, Thread
from queue import Queue

import struct
import random


TIMEOUT = 3
THREADS = 1


def parse_args():
    parser = argparse.ArgumentParser(description='Yet another port scanner')
    parser.add_argument('-t', '--tcp', action='store_true', help='Scan TCP')
    parser.add_argument('-u', '--udp', action='store_true', help='Scan UDP')
    parser.add_argument('host', type=str, default=['8.8.8.8'], help='Remote host')
    parser.add_argument('-p', '--ports', type=int, nargs=2, default=['1', '65535'], help='Define port range')
    return parser.parse_args().__dict__


def validate_ports(port_range: list) -> Tuple[int, int]:
    """ Проверка валидности портов 
        (номер первого порта меньше второго и оба номера 
        расположены в диапазоне допустимых значений) """
    a, b = port_range
    return (a, b) if (a < b and 1 < a < 65535 and 1 < b < 65535) else (None, None)


def scan(tcp: bool, udp: bool, host: str, ports: List[str]):
    port_start, port_end = validate_ports(ports)
    if port_start:
        scanner = Scanner(tcp, udp, host, port_start, port_end, TIMEOUT, THREADS)
        scanner.run()


class Scanner:
    def __init__(self, tcp, udp, host: str, port_start: int, port_end: int, timeout=1.0, threadcount=10):
        self.tcp = tcp
        self.udp = udp
        self.host = host
        self.timeout = timeout
        self.threadcount = threadcount
        self.port_range = range(port_start, port_end + 1)
        self.ports_queue = Queue()
        self._lock = Lock()
        self._condition = threading.Condition(self._lock)
        self._ports_active = []
        self._ports_being_checked = []  # перечень проверяемых портов в текущий момент
        self._next_port = port_start
        self._last_port = port_end

    def run(self):
        try:
            while True:
                self._condition.acquire()  # блокируем, во имя избежания коллизий
                while len(self._ports_being_checked) >= self.threadcount:
                    # все потоки заняты работой, ждем пока кто-нибудь освободится
                    self._condition.wait()
                slots_available = self.threadcount - len(self._ports_being_checked)
                self._condition.release()  # снимаем блокировку
                if self._next_port > self._last_port:
                    return
                # print ("Checking {} - {}".format(self._next_port, self._next_port+slots_available))    
                for i in range(slots_available):  # запустить пачку потоков
                    self.start_another_thread()
        except AllThreadsStarted as ex:
            print ("All threads started ...")
        except:
            print_exc()

    def start_another_thread(self):
        """ Запускаем проверку очередного порта в новом потоке
            (берем номер очередного порта, запускаем его в обработку, 
            записываем номер порта в список обрабатываемых в текущий момент)"""
        # if self._next_port > self._last_port:
            # return
        port = self._next_port
        self._next_port += 1
        t = threading.Thread(target=self.check_port, args=(port,))
        with self._lock:
            self._ports_being_checked.append(port)
        t.start()

    def check_port(self, port):
        """ Отрабатывает проверку порта и по завершению убирает 
            номер порта из списка обрабатываемых """
        try:
            self.check_port_(port)
        finally:
            self._condition.acquire()
            self._ports_being_checked.remove(port)
            self._condition.notifyAll()
            self._condition.release()

    def check_port_(self, port):
        if self.tcp:
            self.check_tcp(port)
        if self.udp:
            self.check_udp(port)

    def check_tcp(self, port):
        """ Если удалось подключиться значит порт доступен/открыт """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket.AF_INET - Семейство сокетов IPv4, socket.SOCK_STREAM - TCP
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # ???
        s.settimeout(self.timeout)
        try:
            # s.connect((self.host, port))
            resp = s.connect_ex((self.host, port))  # тот же connect, но с ошибкой если она была (0 если всё ОК)
            try:  
                response = str(s.recv(4096).decode('utf-8'))  # если к сокет удалось открыть то послушает, может что-нибудь скажет
            except socket.timeout:  
                s.send(f'GET / HTTP/1.1\n\n'.encode())  # если по таймауту ничего не сказал - спросим сами
                response = s.recv(4096).decode('utf-8')
            
            protocol = self.get_protocol(response)
            with self._lock:
                self._ports_active.append(port)
                print ("Found active port  TCP: {}  Protocol: {}".format(port, protocol))

            s.close()

        except socket.timeout as ex:  # таймаут
            return
        # except socket.error:
            # print("\ Server not responding !!!!")
            # sys.exit()
        # except (OSError, ConnectionRefusedError):  #???
        #     pass
        # except PermissionError:
        #     with self._lock:
        #         print(f'TCP {port}: Not enough rights')
        # except:
        #     print_exc()

    def check_udp(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        # try:
        pkg = self._build_packet()
        # r= s.connect_ex((self.host, port)) 
        s.sendto(pkg, (self.host, port))
        # s.sendto(b'Ok', (self.host, port))
        r = s.recv(4096)
        rr = str(r)

        resp = repr(r)
        a, b = s.getsockname()
        # data, addr = s.recvfrom(1024)
        # resp = s.recv
        protocol = self.get_protocol(resp)
        print(f'UDP {port} {protocol}')

        s.close()
        # except socket.timeout:
            # pass

    def _build_packet(self):
        url = 'www.google.com'
        randint = random.randint(0, 65535)
        packet = struct.pack(">H", randint)  # Query Ids (Just 1 for now)
        packet += struct.pack(">H", 0x0100)  # Flags
        packet += struct.pack(">H", 1)  # Questions
        packet += struct.pack(">H", 0)  # Answers
        packet += struct.pack(">H", 0)  # Authorities
        packet += struct.pack(">H", 0)  # Additional
        split_url = url.split(".")
        for part in split_url:
            packet += struct.pack("B", len(part))
            for s in part:
                packet += struct.pack('c',s.encode())
        packet += struct.pack("B", 0)  # End of String
        packet += struct.pack(">H", 1)  # Query Type
        packet += struct.pack(">H", 1)  # Query Class
        return packet


    @staticmethod
    def get_protocol(response: str) -> str:
        """
        # TCP:  NTP, DNS, FTP, SSH, Telnet, SMTP,
        #       HTTP, POP3, IMAP, SNTP, BGP, HTTPS, LDAPS, LDAPS
        # UDP: DNS, TFTP, NTP, SNTP, LDAPS, LDAPS
        """
        if 'HTTP/1.1' in response:
            return 'HTTP'
        if 'SMTP' in response:
            return 'SMTP'
        if 'IMAP' in response:
            return 'IMAP'
        if 'OK' in response:
            return 'POP3'
        return ''



class AllThreadsStarted(Exception): pass


class PortScannerError(Exception):
    message: str


class BadPortRangeError(PortScannerError):
    def __init__(self, port_range):
        self.message = f'Bad port range {port_range}'


if __name__ == "__main__":
    try:
        args = parse_args()
        scan(**args)

    except KeyboardInterrupt:
        print('\nTerminated.')
        exit()
    # scanner = IPv4PortScanner(domain=domain, port_range=(port_s, port_e))
    # scanner.run()