import argparse  # для разбора аргументов
import getpass   # для возможности ввода пароля не отображая его в консоли

from imaplib import IMAP4, IMAP4_SSL
import email
from email.header import decode_header
from typing import List

import re  # для использования регулярок 

DEBUG = True

if DEBUG:
    LOGIN = "fantom.krez@mail.ru"
    PASSW = "0kSiWxCoLcFFeEoMF2Xr"  #"a1224364860"
    SERVER = 'imap.mail.ru'

"""
TODO: Написать скрипт выводящий инфо о письмах в ящике
Параметры:
 -h/--help   справка
 --ssl       разрешить использование ssl, если сервер поддерживает (по умолчанию не использовать)
 -s/--server адрес IMAP-сервера  (адрес[:порт], порт по умолчанию 143)
 -n N1 [N2]  диспазон писем
 -u/--user   Имя пользователя (пароль спросить после запуска)

 Оценочные:
 * вывод заголовков писем нормализованным списком с полями: кому, от кого, тема, дата, размер письма.
 * декодирование заголовков From/Subject  (?)
 * работа по защищенному соединению (SSL)
 * вывод кол-ва аттачей, их имен и размеров
 **? обязательна обработка ответов сервера, в том числе многострочных

 Ход работы:
 (+) 1. реализовать разборщик консольных атрибутов (обработчик входных параметров)
 ( ) 2. реализовать почтовый просмотрщик
    (+) 2.1 Сделать ящик и включить в нем доступ по IMAP 
    (+) 2.2 Убедиться что авторизация проходит и с сервером есть связь
    (+) 2.3 Получить инфу о количестве писем (N)
    (+) 2.4 Получить N писем
    (+) 2.5 Показать N писем
        (+) 2.5.1 Декодировать заголовок и остальные атрибуты письма
        ( ) 2.5.2 Сделать форматирование - для корректного отображения данных в виде таблицы
        ( ) 2.5.3 Сделать вывод вложенных документов
        (+) 2.6 Получать вложения
        (+) 2.7 Показывать вложения
"""

def get_args():
    """ Проверка входных аргументов """
    parser = argparse.ArgumentParser(description='Еще один не нужный миру почтовый клиент')
    parser.add_argument('-s', '--server', type=str,  help='Адрес IMAP-сервера  (адрес[:порт])')
    parser.add_argument('-n', type=int, nargs='*', default=['-1'],  help='Выбрать диапазон писем')
    parser.add_argument('--ssl', action="store_true", help='Разрешить использование ssl')
    parser.add_argument('-u', '--user', type=str, help='Логин пользователя')

    return parser.parse_args().__dict__


class IMAPClient:
    def __init__(self, ssl: bool, server: str, n: List[str], user: str):
        self.ssl = ssl
        server_buf = server.split(":")
        self.server = server_buf[0]
        try:
            self.port = int(server_buf[1])
        except:
            self.port = 143
        self.user = user
        a = len(n) == 0
        b = len(n) > 2
        c = len(n) == 2 and (int(n[0]) > int(n[1]) or int(n[0]) < 0 or int(n[1]) < 0)
        if a or b or c:
            print('Указан некорректный интервал')
            return
        self.interval = n

    def run(self):
        print(f"Подключение к серверу: {self.server}")
        # TODO: добавить проверку что подключение к серверу прошло успешно
        if self.ssl:
            mailbox = IMAP4_SSL(self.server)
        else:
            mailbox = IMAP4(self.server)
        print(f"Подключено. Пользователь: {self.user}...")
        # passw = getpass.getpass("Введите пароль: ")
        passw = "0kSiWxCoLcFFeEoMF2Xr"
        # TODO: добавить проверку успешной авторизации
        mailbox.login(self.user, passw)
        print("Авторизация прошла успешно. Считываем сообщения.")
        status, select_data = mailbox.select('INBOX')  # status=='OK'
        messages_count = select_data[0].decode('utf-8')
        status, search_data = mailbox.search(None, 'ALL')  # получаем список id 

        all_id = search_data[0].split()
        if not self.check_interval(all_id):
            print("Указан неверный интервал")
            return

        if self.interval == ['-1']:
            for message_id in all_id:
                message_id_str = message_id.decode('utf-8')
                print("Fetching message {} of {}".format(message_id_str, messages_count))
                letter = self.get_letter(mailbox, message_id)

                # Надо сделать форматирование вывода результатов
                print(letter)
        else:
            if len(self.interval) == 1:
                start_id = self.interval[0]
                for message_id in all_id:
                    if int(message_id) < start_id:  # от указанного до конца
                        continue
                    # if message_id >= start_id:  # от первого до указанного
                        # return
                    message_id_str = message_id.decode('utf-8')
                    print("Fetching message {} of {}".format(message_id_str, messages_count))
                    letter = self.get_letter(mailbox, message_id)

                    # Надо сделать форматирование вывода результатов
                    print(letter)
            else:
                start_id = self.interval[0]
                stop_id = self.interval[1]
                for message_id in all_id:
                    if int(message_id) < start_id:
                        continue
                    if int(message_id) > stop_id:
                        return
                    message_id_str = message_id.decode('utf-8')
                    print("Fetching message {} of {}".format(message_id_str, messages_count))
                    letter = self.get_letter(mailbox, message_id)

                    # TODO: Надо сделать форматирование вывода результатов
                    print(letter)

        mailbox.logout()

    def check_interval(self, ids) -> bool:
        buf = [int(i) for i in ids]
        if self.interval == ['-1']:
            return True
        elif len(self.interval) == 1:
            return self.interval[0] in buf
        elif len(self.interval) == 2:
            return self.interval[0] in buf and self.interval[1] in buf

    def get_letter(self, mailbox, id):
        """ Получить письмо, разобрать по компонентам """
        status, data = mailbox.fetch(id, '(RFC822)')
        msg = email.message_from_bytes(data[0][1], _class = email.message.EmailMessage)
        raw_msg_to = msg['To']  # Кому
        raw_msg_from = msg['From']  # От кого
        raw_sub = msg['Subject']  # Заголовок письма
        msg_to = dd(raw_msg_to)
        msg_from = dd(raw_msg_from)
        subject = dd(raw_sub)
        date = msg['Date']
        timestamp = email.utils.parsedate_tz(msg['Date'])  # Время отправления (списком)
        year, month, day, hour, minute, second = timestamp[:6]
        msg_size = 0  # размер письма в байтах
        attaches = []
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode('utf-8')
                msg_size += len(body)

            fileName = part.get_filename()
            if bool(fileName):
                size = len(part.get_payload(decode=True))
                attaches.append({'name':fileName, 'size':size})
        attaches_len = len(attaches)

        return msg_from, msg_to, subject, timestamp, msg_size, attaches


def dd(data):
    """ декодер заголовков """
    return str(email.header.make_header(email.header.decode_header(data)))


if __name__=="__main__":
    IMAPClient(**get_args()).run()
    s = 23
