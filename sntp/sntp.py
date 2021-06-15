""" Параметры:
-d  delay, может быть как положительным, так и отрицательным целым числом,
    означающим число секунд, на которое должны обманывать клиентов,
    по умолчанию 0
--port, -p - порт, который слушаем, по умолчанию 123

./sntp.py -d 5
сервер в ответе добавляет 5 секунд к текущему времени
Сервер сообщает на stdout о начале работы, а при подключении очередного
клиента выводит его ip-адрес
"""

import argparse
import socket

from SNTPserver import SNTPserver


def parse_args():
    parser = argparse.ArgumentParser(description='SNTP experimental server')
    parser.add_argument('-d', '--delay', type=int, default=20.0,
                        help='Set delay')
    parser.add_argument('-p', '--port', type=int, nargs=1, default=123,
                        help='Listen port')
    return parser.parse_args().__dict__


def start(delay: int, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('localhost', port))
    s.settimeout(1)

    sntp = SNTPserver(s, delay)
    sntp.run()


if __name__ == "__main__":
    try:
        args = parse_args()
        start(**args)

    except KeyboardInterrupt:
        print('\nTerminated.')
        exit()
