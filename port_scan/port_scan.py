"""
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
import socket
import threading
from traceback import print_exc
from typing import List, Tuple
from threading import Lock
from queue import Queue
from imaplib import IMAP4, IMAP4_SSL
from ssl import SSLError

import struct
import random


TIMEOUT = 3
THREADS = 5


def parse_args():
    parser = argparse.ArgumentParser(description='Yet another port scanner')
    parser.add_argument('-t', '--tcp', action='store_true', help='Scan TCP')
    parser.add_argument('-u', '--udp', action='store_true', help='Scan UDP')
    parser.add_argument(
        'host',
        type=str,
        default=['8.8.8.8'],
        help='Remote host'
        )
    parser.add_argument(
        '-p', '--ports',
        type=int,
        nargs=2,
        default=['1', '65535'],
        help='Define port range'
        )
    return parser.parse_args().__dict__


def validate_ports(port_range: list) -> Tuple[int, int]:
    """ Проверка валидности портов
        (номер первого порта меньше второго и оба номера
        расположены в диапазоне допустимых значений) """
    a, b = port_range
    valid = a < b and 1 < a < 65535 and 1 < b < 65535
    return (a, b) if valid else (None, None)


def scan(tcp: bool, udp: bool, host: str, ports: List[str]):
    port_start, port_end = validate_ports(ports)
    if port_start:
        scanner = Scanner(
            tcp, udp, host, (port_start, port_end), TIMEOUT, THREADS)
        scanner.run()


class Scanner:
    def __init__(self, tcp, udp, host: str, ports, timeout=1.0, t_count=10):
        self.tcp = tcp
        self.udp = udp
        self.host = host
        self.timeout = timeout
        self.threadcount = t_count
        self.port_range = range(ports[0], ports[1] + 1)
        self.ports_queue = Queue()
        self._lock = Lock()
        self._condition = threading.Condition(self._lock)
        self._ports_active = []
        # перечень проверяемых портов в текущий момент
        self._ports_being_checked = []
        self._next_port, self._last_port = ports

    def run(self):
        try:
            while True:
                self._condition.acquire()  # блокируем
                while len(self._ports_being_checked) >= self.threadcount:
                    # ждем если все потоки заняты работой
                    self._condition.wait()
                l_ports = len(self._ports_being_checked)
                slots_available = self.threadcount - l_ports
                self._condition.release()  # снимаем блокировку
                if self._next_port > self._last_port:
                    return
                for i in range(slots_available):  # запустить пачку потоков
                    self.start_another_thread()
        except AllThreadsStarted:
            print("All threads started ...")
        except Exception:
            print_exc()

    def start_another_thread(self):
        """ Запускаем проверку очередного порта в новом потоке
            (берем номер очередного порта, запускаем его в обработку,
            записываем номер порта в список обрабатываемых в текущий момент)"""
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
        # socket.AF_INET - Семейство сокетов IPv4, socket.SOCK_STREAM - TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            resp = s.connect_ex((self.host, port))  # 0 если всё ОК
            if resp != 0:  # подключение не удалось
                return
            protocol = self.check_socket_protocol(s, port, 'tcp')
            with self._lock:
                self._ports_active.append(port)
                print("TCP: {} {}".format(port, protocol))
        except socket.timeout:
            return
        finally:
            s.close()

    def check_udp(self, port):
        """ Если удалось подключиться значит порт доступен/открыт """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        try:
            resp = s.connect_ex((self.host, port))
            if resp != 0:  # подключение не удалось
                return
            protocol = self.check_socket_protocol(s, port, 'udp')
            with self._lock:
                self._ports_active.append(port)
                print('UDP {} {}'.format(port, protocol))
        except socket.timeout:
            return
        finally:
            s.close()

    def check_socket_protocol(self, s, port, protocol):
        """ Определяем протокол порта """
        res = ""
        if self._is_dns(s, port):
            res = "DNS"
        elif self._is_http(s):
            res = "HTTP"
        elif self._is_smtp(s):
            res = "SMTP"
        elif self._is_ntp(s):
            res = "NTP"
        elif protocol=='tcp' and self._is_pop3(s, port):
            res = "POP3"
        elif protocol=='tcp' and self._is_imap_ssl(port):
            res = "IMAP_SSL"
        elif protocol=='tcp' and self._is_imap_no_ssl(port):
            res = "IMAP"
        elif self._is_something(s, port):
            res = "SOMETHING"
        # если проверки ничего не показали
        # покажем стандартный протокол порта (если есть)
        else:
            try:
                res = "may be standart {}".format(
                    socket.getservbyport(port, protocol).upper())
            except Exception:
                res = "Unknown"

        return res

    def _is_dns(self, s, port):
        """ А может ДНС? """
        try:
            pkg = self._build_dns_packet()
            s.sendto(pkg, (self.host, port))
            response = s.recv(1024)
        except Exception:
            return False
        if len(response) > 0:  # TODO: check response
            return True
        return False

    def _build_dns_packet(self):
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
                packet += struct.pack('c', s.encode())
        packet += struct.pack("B", 0)  # End of String
        packet += struct.pack(">H", 1)  # Query Type
        packet += struct.pack(">H", 1)  # Query Class
        return packet

    def _is_something(self, s, port):
        # s.sendto(b"Hello world!", (self.host, port))
        try:
            s.send(b"Hello world!")
            response = s.recv(1024)
        except Exception:
            return False

        if len(response) > 0:  # что-то ответило
            return True
        return False

    def _is_http(self, s):
        try:
            req = "GET / HTTP/1.1\r\n\r\n".encode()
            s.send(req)
            response = s.recv(2048)
        except Exception:
            return False

        if 'HTTP/1.1' in response:
            return True
        return False

    def _is_smtp(self, s):
        try:
            recv = s.recv(1024)
            if len(recv)==0:
                return False
            if recv[:3] != '220': # не получен код SMTP Service ready
                return False
            heloCommand = 'HELO test.com\r\n'.encode()
            s.send(heloCommand)
            recv1 = s.recv(1024)
        except Exception:
            return False

        if recv1[:3] == '250': # Requested mail action okay
            return True
        return False

    def _is_ntp(self, s):
        return False
        req = "GET / HTTP/1.1\r\n\r\n".encode()
        s.send(req)
        response = s.recv(2048)
        # http_response = repr(response)
        if 'HTTP/1.1' in response:
            return True
        else:
            return False

    def _is_pop3(self, s, port):
        """ pop3 ответы всегда начинаются с '+OK' """
        try:
            response = s.recv(2048)
            if 'OK' in response[:3]:
                return True
            else:
                resp = s.send(b'USER test\r\n')
        except Exception:
            return False

        if 'OK' in resp:
            return True
        return False

    def _is_imap_ssl(self, port):
        try:
            mailbox = IMAP4_SSL(self.host, port=port)
        except Exception:
            return False
        return True

    def _is_imap_no_ssl(self, port):
        try:
            mailbox = IMAP4(self.host, port=port)
        except Exception:
            return False
        return True

    # устарело
    # @staticmethod
    # def get_protocol(reply_in, port, protocol) -> str:
    #     """
    #     # TCP:  NTP, DNS, FTP, SSH, Telnet, SMTP,
    #     #       HTTP, POP3, IMAP, SNTP, BGP, HTTPS, LDAPS, LDAPS
    #     # UDP: DNS, TFTP, NTP, SNTP, LDAPS, LDAPS
    #     """
    #     reply = reply_in[:100]
    #     try:
    #         # Вариант для определения по сигнатуре
    #         if 'HTTP/1.1' in reply:
    #             return 'looks like HTTP'
    #         if 'SMTP' in reply:
    #             return 'looks like SMTP'
    #         if 'IMAP' in reply:
    #             return 'looks like IMAP'
    #         if 'OK' in reply:
    #             return 'looks like POP3'
    #         # Вариант для дефолтных портов
    #         # (Может работать некорректно т.к. показывает какой
    #         # обычно протокол работает на указанном порту, но ничего
    #         # не мешает людям использовать почти любой другой для своих целей)
    #         return socket.getservbyport(port, protocol).upper()
    #     except Exception:
    #         return 'Unknown'


class AllThreadsStarted(Exception):
    pass


if __name__ == "__main__":
    try:
        args = parse_args()
        scan(**args)

    except KeyboardInterrupt:
        print('\nTerminated.')
        exit()

"""
Как это работает?
==================================================
Вызов - разбираются аргументы и передаются в scan()
  scan()  Вызывает проверку указанных портов validate_ports() и если всё ок -
  Создает экземпляр класса Scanner и запускает его метод scanner.run()

    run() - выполняется пока есть непроверенные порты.
    * "аккуратно", т.е. с блокировкой ресурсов на время их проверки, провеярет
        сколько потоков заняты работой, если занято меньше указанного в THREADS
        (self.threadcount), то вычисляет сколько конкретно еще он может
        запустить (slots_available) и запускает, вызывая start_another_thread()

      start_another_thread() -
      * запускает в обработку порт с очередным номером (port) в новый поток,
        методом self.check_port() ,
      * вычисляет следующий для проверки (self._next_port),
      * пополняет список проверяемых в текущий момент портов
        (self._ports_being_checked)

        check_port() -
        * вызывает непосредственно проверку порта (self.check_port_()),
        * по завершению проверки "аккуратно" убирает порт из списка
            обрабатываемых

          check_port_() -
          * если указаны tcp/udp делает соответствующие вызовы

            check_tcp() - проверяет порт хоста
            * настраивает сокет
            * пытается подключиться (s.connect_ex()), если удалось - половина
                успеха
                * пытается в обмен сообщениями, если удалось получить сообщение
                    пробует его декодировать в utf-8 и проверить на предмет
                    наличия специфичных для разного рода протоколов ключевых
                    слов методом get_protocol()
                * особо не важно удалось общение или нет, раз удалось
                    подключиться, поэтому "аккуратно" записывает порт в список
                    активных (self._ports_active) и также "аккуратно" выводит
                    сообщение на экран

            check_udp() - проверяет порт хоста
            * настраивает сокет
            * пытается подключиться (s.connect_ex()), если удалось - успех
                * пытается в обмен сообщениями - почти всегда общение не
                удастся, так как принимающий сервер вероятно просто
                ===> фильтрует входящие пакеты <===
                * опять же "аккуратно" записывает порт в список активных
                    (self._ports_active)
                * "аккуратно" выводит сообщение на экран
                ** между делом использует метод _build_packet() для сборки
                    кастом-пакета, оставлено было лишь с одной целью - чтобы
                    было, особо это не нужно и кроме как при "общении" с одним
                    из серверов гугла ("142.250.185.78") не применимо
                    (кстати гугл как-то интересно откликался по этому адресу
                     по udp, порт 53, который вроде DNS, так что не суть...)

  get_protocol() - пытается в угадывание протокола
    * в ифах - предположительно ключевые слова, который могут присутствовать
        в ответах сервера, соответственно роли порта
    * socket.getservbyport() - возвращает стандартную/дефолт роль порта
"""
