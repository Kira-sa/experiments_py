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

import struct
import random


TIMEOUT = 3
THREADS = 10


def parse_args():
    parser = argparse.ArgumentParser(description='Yet another port scanner')
    parser.add_argument('-t', '--tcp', action='store_true', help='Scan TCP')
    parser.add_argument('-u', '--udp', action='store_true', help='Scan UDP')
    parser.add_argument('host', type=str, default=['8.8.8.8'], 
        help='Remote host')
    parser.add_argument('-p', '--ports', type=int, nargs=2, 
        default=['1', '65535'], help='Define port range')
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
        scanner = Scanner(tcp, udp, host, port_start, port_end, 
            TIMEOUT, THREADS)
        scanner.run()


class Scanner:
    def __init__(self, tcp, udp, host: str, port_start: int, 
                port_end: int, timeout=1.0, threadcount=10):
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
        # перечень проверяемых портов в текущий момент
        self._ports_being_checked = []
        self._next_port = port_start
        self._last_port = port_end

    def run(self):
        try:
            while True:
                self._condition.acquire()  # блокируем
                while len(self._ports_being_checked) >= self.threadcount:
                    # ждем если все потоки заняты работой
                    self._condition.wait()
                slots_available = self.threadcount - len(self._ports_being_checked)
                self._condition.release()  # снимаем блокировку
                if self._next_port > self._last_port:
                    return
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
        reply = ''
        try:
            resp = s.connect_ex((self.host, port))  # 0 если всё ОК
            if resp!=0:
                # Вывод инфо если подключение не удалось (по разным причинам)
                # with self._lock:
                    # print("Ошибка при подключении к порту {}".format(port))
                return
            # если к сокет удалось открыть то послушает, 
            # может что-нибудь скажет
            reply_raw = s.recv(4096)  
            try: 
                # попробуем привести сообщение в осмысленный вид
                reply = str(reply_raw.decode('utf-8'))  

            except UnicodeDecodeError:  # Сообщение не удалось декодировать в utf-8
                # with self._lock:
                #     print("{}".format(reply_raw))
                pass
            except socket.timeout: 
                # если по таймауту ничего не сказал - спросим сами
                s.send(f'GET / HTTP/1.1\n\n'.encode())  
                reply = s.recv(4096).decode('utf-8')
            
            protocol = self.get_protocol(reply, port, "tcp")
            with self._lock:
                self._ports_active.append(port)
                # print ("Found active port  TCP: {} \
                # Protocol: {}".format(port, protocol))
                print ("TCP: {}  Protocol: {}".format(port, protocol))
            s.close()

        except socket.timeout as ex:  # таймаут
            return
        # возможные ошибки при использовании s.connect(), бесполезно при s.connect_ex()
        # except ConnectionRefusedError:  # сервер отклонил подключение
        #     return
        # except ConnectionResetError:  # сервер сбросил подключение
        #     return


    def check_udp(self, port):
        """ Если удалось подключиться значит порт доступен/открыт """
        reply = ''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        pkg = self._build_packet()
        resp = s.connect_ex((self.host, port)) 
        if resp != 0:  # подключение не прошло
            return
        try:
            # a = s.sendto(pkg, (self.host, port))
            a = s.sendto(b"Hello world!", (self.host, port))
            reply = s.recv(1024)
        except socket.timeout:
            # print("Общения не удалось\n")
            pass
            # return
        protocol = self.get_protocol(reply, port, "udp")
        with self._lock:
            self._ports_active.append(port)
            # print(reply)
            # print('Found active port  UDP {} {}'.format(port, protocol))
            print('UDP {} {}'.format(port, protocol))
        s.close()


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
    def get_protocol(reply_in, port, protocol) -> str:
        """
        # TCP:  NTP, DNS, FTP, SSH, Telnet, SMTP,
        #       HTTP, POP3, IMAP, SNTP, BGP, HTTPS, LDAPS, LDAPS
        # UDP: DNS, TFTP, NTP, SNTP, LDAPS, LDAPS
        """
        reply = reply_in[:100]
        try:
            # Вариант для определения по сигнатуре
            if 'HTTP/1.1' in reply:
                return 'looks like HTTP'
            if 'SMTP' in reply:
                return 'looks like SMTP'
            if 'IMAP' in reply:
                return 'looks like IMAP'
            if 'OK' in reply:
                return 'looks like POP3'
            # Вариант для дефолтных портов 
            # (Может работать некорректно т.к. показывает какой 
            # обычно протокол работает на указанном порту, но ничего 
            # не мешает людям использовать почти любой другой для своих целей)
            return socket.getservbyport(port, protocol).upper()
        except:
            return 'Unknown'


class AllThreadsStarted(Exception): pass


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
        сколько потоков заняты работой, если занято меньше указанного в THREADS (self.threadcount),
        то вычисляет сколько конкретно еще он может запустить (slots_available) и запускает,
        вызывая start_another_thread()
      
      start_another_thread() - 
      * запускает в обработку порт с очередным номером (port) в новый поток, методом self.check_port() ,
      * вычисляет следующий для проверки (self._next_port), 
      * пополняет список проверяемых в текущий момент портов (self._ports_being_checked)
        
        check_port() - 
        * вызывает непосредственно проверку порта (self.check_port_()),
        * по завершению проверки "аккуратно" убирает порт из списка обрабатываемых

          check_port_() - 
          * если указаны tcp/udp делает соответствующие вызовы

            check_tcp() - проверяет порт хоста
            * настраивает сокет
            * пытается подключиться (s.connect_ex()), если удалось - половина успеха
                * пытается в обмен сообщениями, если удалось получить сообщение 
                пробует его декодировать в utf-8 и проверить на предмет наличия 
                специфичных для разного рода протоколов ключевых слов методом get_protocol()
                * особо не важно удалось общение или нет, раз удалось подключиться,
                поэтому "аккуратно" записывает порт в список активных (self._ports_active) 
                и также "аккуратно" выводит сообщение на экран

            check_udp() - проверяет порт хоста
            * настраивает сокет
            * пытается подключиться (s.connect_ex()), если удалось - успех
                * пытается в обмен сообщениями - почти всегда общение не удастся,
                так как принимающий сервер вероятно просто 
                ===> фильтрует входящие пакеты <===
                * опять же "аккуратно" записывает порт в список активных (self._ports_active) 
                * "аккуратно" выводит сообщение на экран
                ** между делом использует метод _build_packet() для сборки кастом-пакета,
                оставлено было лишь с одной целью - чтобы было, особо это не нужно
                и кроме как при "общении" с одним из серверов гугла ("142.250.185.78")
                не применимо (кстати гугл как-то интересно откликался по этому адресу по udp, порт 53,
                который вроде DNS, так что не суть...)

  get_protocol() - пытается в угадывание протокола
    * в ифах - предположительно ключевые слова, который могут присутствовать 
        в ответах сервера, соответственно роли порта
    * socket.getservbyport() - возвращает стандартную/дефолт роль порта
"""