

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
# import socket+
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM, socket, timeout
import threading 
from datetime import datetime, time
from traceback import print_exc
import re
from typing import List, Tuple
from threading import Lock, Thread
from queue import Queue


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
        scanner = Scanner(host, port_start, port_end, 1, 10)
        scanner.start_scan(tcp, udp)


class Scanner:
    def __init__(self, host: str, port_start: int, port_end: int, timeout=1.0, threadcount=10):
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
                # if self._next_port > self._last_port:
                #     return
                print ("Checking {} - {}".format(self._next_port, self._next_port+slots_available))    
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
        if self._next_port > self._last_port:
            return
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
        "If connects then port is active"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.domain, port))
            with self._lock:
                self._ports_active.append(port)
            print ("Found active port {}".format(port))
            sock.close()
        except socket.timeout as ex:
            return
        except:
            print_exc()


#  ---------------------------------------------------
#  ---------------------------------------------------

    def start_scan(self, tcp: bool, udp:bool):
        threads = []
        for port in self.port_range:
            if not udp or tcp:
                self.ports_queue.put(port)
                t = Thread(target=self.thread_scan, args=(self.scan_tcp_port,))
                threads.append(t)
            if not tcp or udp:
                self.ports_queue.put(port)
                t = Thread(target=self.thread_scan, args=(self.scan_udp_port,))
                threads.append(t)
        for thread in threads:
            thread.start()
        self.ports_queue.join()
    
    def thread_start(self, scan_func):
        port = self.ports_queue.get()
        scan_func(port)
        self.ports_queue.task_done()

    def scan_udp_port(self, port: int):
        return
        try:
            with socket(AF_INET, SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.sendto(b'hello', (self.host, port))
                response = sock.recv(1024).decode('utf-8')
            protocol = self.get_protocol(response)
            print(f'UDP {port} {protocol}')
        except (timeout, OSError):
            pass
        except PermissionError:
            with self._lock:
                print(f'UDP {port}: Not enough rights')

    def scan_tcp_port(self, port: int):
        try:
            with socket(AF_INET, SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                sock.connect((self.host, port))
                try:
                    response = str(sock.recv(1024).decode('utf-8'))
                except timeout:
                    sock.send(f'GET / HTTP/1.1\n\n'.encode())
                    response = sock.recv(1024).decode('utf-8')
            protocol = self.get_protocol(response)
            with self._lock:
                print(f'TCP {port} {protocol}')
        except (OSError, ConnectionRefusedError):
            pass
        except PermissionError:
            with self._lock:
                print(f'TCP {port}: Not enough rights')

    @staticmethod
    def get_protocol(response: str) -> str:
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


class IPv4PortScanner(object):
    def __init__(self, domain, timeout=1.0, port_range=(1024, 65535), threadcount=10):
        self.domain = domain  # цель
        self.timeout = timeout
        self.port_range = port_range
        self.threadcount = threadcount
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._ports_active  = []
        self._ports_being_checked = []

        self._next_port = self.port_range[0]
        self._last_port = self.port_range[1]

    def check_port_(self, port):
        "If connects then port is active"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.domain, port))
            with self._lock:
                self._ports_active.append(port)
            print ("Found active port {}".format(port))
            sock.close()
        except socket.timeout as ex:
            return
        except:
            print_exc()
            # pdb.set_trace()

    def check_port(self, port):
        "updates self._ports_being_checked list on exit of this method"
        try:
            self.check_port_(port)
        finally:
            self._condition.acquire()
            self._ports_being_checked.remove(port)
            self._condition.notifyAll()
            self._condition.release()

    def start_another_thread(self):
        if self._next_port > self._last_port:
            return
        port             = self._next_port
        self._next_port += 1
        t = threading.Thread(target=self.check_port, args=(port,))
        # update books
        with self._lock:
            self._ports_being_checked.append(port)
        t.start()

    def run(self):
        try:
            while True:
                self._condition.acquire()  # блокируем ресурсы, во имя избежания коллизий
                while len(self._ports_being_checked) >= self.threadcount:
                    # we wait for some threads to complete the task
                    self._condition.wait()
                slots_available = self.threadcount - len(self._ports_being_checked)
                self._condition.release()  # освобождаем ресурсы
                print ("Checking {} - {}".format(self._next_port, self._next_port+slots_available))
                if self._next_port > self._last_port:
                    return
                for i in range(slots_available):  # запустить пачку потоков
                    self.start_another_thread()
        except AllThreadsStarted as ex:
            print ("All threads started ...")
        except:
            print_exc()



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