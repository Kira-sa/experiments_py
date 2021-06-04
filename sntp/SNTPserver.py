import queue
import time
import select
import struct
import sys
import threading


class SNTPserver:
    """ Класс с описанием сервера,
        должен делать 2 вещи:
            1. слушать обращения
            2. отвечать на обращения
    """
    def __init__(self, sock, delay) -> None:
        self.sock = sock
        self.delay = delay
        self.task = queue.Queue()

    def run(self):
        """ Поднять сервер, 
            слушать подключения/запросы, 
            врать в ответ
        """
        print("SNTP server start")
        receiver = threading.Thread(target=self.listen_socket)
        receiver.start()
        sender = threading.Thread(target=self.send_response)
        sender.start()

    def listen_socket(self):
        while True:
            timeout = 3
            ready_to_read, _, _ = select.select([self.sock], [], [], timeout)
            if ready_to_read:
                self.add_task(ready_to_read)
    
    def add_task(self, ready_to_read):
        for client in ready_to_read:
            pack_sntp, addr = client.recvfrom(1024)
            print("Connected: {}".format(addr[0]))
            self.task.put((pack_sntp, addr, time.time()))

    def prepare_response(self, request, recive_time):
        return SNTPpack(self.delay, 
                        stratum=3, 
                        version=4, #request.version, 
                        mode=4, # 4 - сервер, 3 - клиент, что бы это ни значило
                        originate_time=request.transmit_timestamp,
                        recive_time=recive_time + self.delay
                        )

    def send_response(self):
        """ Если в очереди есть задания - обрабатываем их """
        while True:
            try:
                if self.task.empty():
                    time.sleep(1)
                # print("Отправляем клиенту ответ")
                req, req_addr, req_time = self.task.get(timeout=1)
                request = SNTPpack()
                request.parse_package(req)  # разбираем запрос клиента
                response = self.prepare_response(request, req_time).create_package() # готовим ответ
                self.sock.sendto(response, req_addr)  # отправляем
            except queue.Empty:
                continue


class SNTPpack():
    SNTP_MODE = {'reserved': 0, 'symmetry active':1, 'symmetry passive':2, 'client': 3, 'server': 4, 'broadcast':5}

    def __init__(self, delay=0, stratum=3, version=4, mode=4, originate_time=0, recive_time=0):
        """ https://labs.apnic.net/?p=462 - описание протокола NTP """
        self.delay = delay      # настраиваемая зарержка/опережение
        self.LI = 0             # Leap Indicator - индикатор коррекции
        self.VN = version       # Version Number (3 bits) - номер версии, в настоящее время = 4
        self.mode = mode        # NTP packet mode
        self.stratum = stratum  # страта (1 Byte) - поле определено для сообщений сервера
        self.poll = 0           # интервал опроса (8 bits, знаковый int) 
        self.precision = 0      # Clock precision - точность системных часов
        self.root_delay = 0     # задержка
        self.root_dispersion = 0  # дисперсия
        self.ref_id = 0         # Reference Identifier - идентификатор источника
        self.ref_timestamp = 0  # время обновления (This field is the time the system clock was last set or corrected, in 64-bit time-stamp format.)
        self.originate_timestamp = originate_time  # начальное время (This value is the time at which the request departed the client for the server, in 64-bit time-stamp format.)
        self.recive_timestamp = recive_time  # время приема (This value is the time at which the client request arrived at the server in 64-bit time-stamp format.)
        self.transmit_timestamp = 0  # время отправки (This value is the time at which the server reply departed the server, in 64-bit time-stamp format.)

    def parse_package(self, data):
        try:
            # !4B3L4Q == !BBBBLLLQQQQ - структура данных
            size = struct.calcsize('!4B3L4Q')
            unpacked = struct.unpack('!4B3L4Q', data[:size])
            self.LI, self.VN, self.mode = self.parse_first_byte(unpacked[0])
            self.transmit_timestamp = struct.unpack('!Q', data[40:48])[0]
        except BaseException:
            print('Invalid SNTP-packet format')

    def parse_first_byte(self, num):
        """ Разбираем побитово первый байт """
        b = bin(num)[2:].rjust(8, '0')  # переводим число в строку с "бинарным" видом '00011011'
        li = int(b[:2], 2)      # первые 2 бита
        vn = int(b[2:5], 2)     # следующие 3 бита
        mode = int(b[5:], 2)    # оставшиеся 3 бита
        return li, vn, mode

    def create_package(self):
        li = self.num_to_bin(self.LI, 2)
        vn = self.num_to_bin(self.VN, 3)
        mode = self.num_to_bin(self.mode, 3)
        start_of_package = f'{li}{vn}{mode}'
        first_byte = int(start_of_package, 2)
        self.transmit_timestamp = time.time() + self.delay
        self.ref_timestamp = self.convert_time_to_sntp(self.transmit_timestamp)
        sntp_recive_timestamp = self.convert_time_to_sntp(self.recive_timestamp)
        transmit_timestamp = sntp_recive_timestamp + self.ref_timestamp

        package = struct.pack('!4B3L2LQ4L', first_byte,     # LI + VN + MODE
                                            self.stratum,   
                                            self.poll,     
                                            self.precision, 
                                            self.root_delay,
                                            self.root_dispersion, 
                                            self.ref_id, 
                                            *self.ref_timestamp, 
                                            self.originate_timestamp,
                                            *transmit_timestamp
                                            )
        return package

    def num_to_bin(self, num, length):
        return bin(num)[2:].rjust(length, '0')

    def convert_time_to_sntp(self, time):
        """ колдунство """
        time_shift = 2208988800
        sec, mill_sec = str(time + time_shift).split('.')
        mill_sec = float('0.{}'.format(mill_sec)) * 2 ** 32
        return int(sec), int(mill_sec)