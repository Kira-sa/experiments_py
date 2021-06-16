import argparse  # для разбора аргументов
import getpass   # для возможности ввода пароля не отображая его в консоли
import re        # для получения размера письма регулярным выражением

from imaplib import IMAP4, IMAP4_SSL
from ssl import SSLError
import email
from typing import List

DEBUG = True

if DEBUG:
    LOGIN = "fantom.krez@mail.ru"
    PASSW = "0kSiWxCoLcFFeEoMF2Xr"  # "a1224364860"
    SERVER = 'imap.mail.ru'

"""
Параметры:
 -h/--help  справка
 --ssl      разрешить использование ssl, если сервер
            поддерживает (по умолчанию не использовать)
 -s/--server адрес IMAP-сервера  (адрес[:порт], порт по умолчанию 143)
 -n N1 [N2] диспазон писем
 -u/--user  Имя пользователя (пароль спросить после запуска)
"""


def get_args():
    """ Проверка входных аргументов """
    parser = argparse.ArgumentParser(description='Еще один не нужный \
        миру почтовый клиент')
    parser.add_argument(
        '-s', '--server',
        type=str,
        help='Адрес IMAP-сервера  (адрес[:порт])'
        )
    parser.add_argument(
        '-n', type=int,
        nargs='*', default=['-1'],
        help='Выбрать диапазон писем'
        )
    parser.add_argument(
        '--ssl',
        action="store_true",
        help='Разрешить использование ssl'
        )
    parser.add_argument(
        '-u', '--user',
        type=str,
        help='Логин пользователя'
        )

    return parser.parse_args().__dict__


class IMAPClient:
    def __init__(self, ssl: bool, server: str, n: List[str], user: str):
        self.ssl = ssl
        server_buf = server.split(":")
        self.server = server_buf[0]
        self.port = 143
        try:
            self.port = int(server_buf[1])
        except Exception:
            pass
        self.user = user
        self.interval = n

    def run(self):
        print("Подключение к серверу: {}".format(self.server))
        try:
            if self.ssl:
                mailbox = IMAP4_SSL(self.server, port=self.port)
            else:
                mailbox = IMAP4(self.server, port=self.port)
        except SSLError as er:
            if er.reason == 'WRONG_VERSION_NUMBER':
                print("Указан неправильный порт")
            else:
                print(er)
            return
        except IMAP4.error as er:
            print("Ошибка подключения к серверу ({})".format(str(er)[2:-1]))
            return
        print("Подключено. Пользователь: {}...".format(self.user))
        passw = getpass.getpass("Введите пароль: ")
        try:
            mailbox.login(self.user, passw)
        except IMAP4.error as er:
            print("Ошибка авторизации ({})".format(str(er)[2:-1]))
            return

        print("Авторизация прошла успешно. Считываем сообщения.")
        mailbox.select('INBOX')  # Выбираем каталог каталог
        # количество писем во входящих
        # messages_count = select_data[0].decode('utf-8')
        # получаем список id писем
        status, search_data = mailbox.search(None, 'ALL')

        all_id = search_data[0].split()
        if not self.check_interval(all_id):
            print("Указан неверный интервал")
            return

        if self.interval == ['-1']:
            for message_id in all_id:
                self.process_letter(mailbox, message_id)
        else:
            if len(self.interval) == 1:
                for message_id in all_id:
                    # от указанного до конца
                    if int(message_id) < self.interval[0]:
                        continue
                    # от первого до указанного
                    # if message_id >= start_id:
                        # return
                    self.process_letter(mailbox, message_id)
            else:
                for message_id in all_id:
                    if int(message_id) < self.interval[0]:
                        continue
                    if int(message_id) > self.interval[1]:
                        return
                    self.process_letter(mailbox, message_id)

        mailbox.logout()

    def formatter(self, letter) -> str:
        """ Подготовка письма для печати (с вложениями если они есть) """
        msg_from, msg_to, subject, date_time, msg_size, attaches = letter
        result = "From: {:35}  To: {:20}  Subject: {:30}  Date: {:15} \
            Size: {:4}  Attaches: {:3}".format(
            msg_from, msg_to, subject, date_time, msg_size, len(attaches))
        att = []
        for i in range(len(attaches)):
            s = "\n\t\tFilename: {:40}   File size: {:10}".format(
                attaches[i]['name'], attaches[i]['size'])
            att.append(s)
        return result + ''.join(att)

    def check_interval(self, ids) -> bool:
        """ Проверка введенных пользователем интервалов """
        buf = [int(i) for i in ids]
        if self.interval == ['-1']:
            return True
        elif len(self.interval) == 1:
            return self.interval[0] in buf
        elif len(self.interval) == 2:
            return self.interval[0] in buf and self.interval[1] in buf

    def process_letter(self, mailbox, message_id):
        """ Получение письма по id от сервера """
        # message_id_str = message_id.decode('utf-8')
        letter = self.get_letter(mailbox, message_id)
        print(self.formatter(letter))

    def get_letter(self, mailbox, id):
        """ Получение письма по id, декодирование,
        разбор по компонентам """
        status, data = mailbox.fetch(id, '(RFC822)')
        # получаем размер письма
        msg_size = int(re.findall('(?<={)(.*?)(?=})', data[0][0].decode())[0])
        msg = email.message_from_bytes(
            data[0][1], _class=email.message.EmailMessage)  # парсим письмо
        raw_msg_to = msg['To']  # Кому
        raw_msg_from = msg['From']  # От кого
        raw_sub = msg['Subject']  # Заголовок письма
        msg_to = dd(raw_msg_to)
        msg_from = dd(raw_msg_from)
        subject = dd(raw_sub)
        timestamp = email.utils.parsedate_tz(msg['Date'])  # Время отправления
        YY, MM, DD, hh, mm, ss = timestamp[:6]
        date_time = '{}:{} {}.{}.{}'.format(hh, mm, DD, MM, YY)
        # msg_size = 0  # размер письма в байтах
        attaches = []
        for part in msg.walk():
            # if part.get_content_type() == 'text/plain':
            #     body = part.get_payload(decode=True).decode('utf-8')
            #     msg_size += len(body)

            fileName = part.get_filename()
            if bool(fileName):
                size = len(part.get_payload(decode=True))
                attaches.append({'name': fileName, 'size': size})

        return msg_from, msg_to, subject, date_time, msg_size, attaches


def dd(data):
    """ декодер заголовков """
    return str(email.header.make_header(email.header.decode_header(data)))


if __name__ == "__main__":
    IMAPClient(**get_args()).run()
