

""" 
Написать сканер TCP- и UDP-портов удалённого компьютера.
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
import threading 
from datetime import datetime
from traceback import print_exc

# parser = argparse.ArgumentParser(description='Еще один не нужный миру почтовый клиент')
# parser.add_argument('-t', type=str, dest='tcp', help='Сканировать TCP')
# parser.add_argument('-u', type=str, dest='udp', help='Сканировать UDP')
# parser.add_argument('-p', '--ports', type=int, nargs='+', dest='ports', help='Выбрать диапазон портов')

# args = parser.parse_args()

target = 'pythonprogramming.net'
#ip = socket.gethostbyname(target)


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


if __name__ == "__main__":
    import sys
    domain  = sys.argv[1]
    port_s  = int(sys.argv[2])
    port_e  = int(sys.argv[3])
    scanner = IPv4PortScanner(domain=domain, port_range=(port_s, port_e))
    scanner.run()