import vk_api
from vk_api.longpoll import VkLongPoll, VkEventType
from vk_api.keyboard import VkKeyboard, VkKeyboardButton, VkKeyboardColor
from vk_api.bot_longpoll import VkBotEventType, VkBotLongPoll
import time
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json

def write_msg(user_id, message, keyboard):
    vk.method('messages.send', {'user_id': user_id, 'message': message, "keyboard": keyboard, "random_id": time.time()})

token = "a0fe4f932f2124985a4e9e906132a28ffbaa2243c57e67bcc89262a4c22753a42ae01b42d5d53327fbdff"

vk = vk_api.VkApi(token=token)
vk_session = vk
vkk = vk_session.get_api()

longpoll = VkLongPoll(vk)

y=1
while y==1:
    for event in longpoll.listen():
        if event.type == VkEventType.MESSAGE_NEW and event.to_me:
            if event.text.lower() == "начать":
                write_msg(
                    user_id = event.user_id,
                    message = "Выбери: зашифровать, расшифровать, или посмотреть сохраненные коды",
                    keyboard = open("keyboard.json", "r", encoding ="UTF-8").read(),
                )
                y = 0
                break
            else:
                write_msg(event.user_id, "напиши начать", keyboard = open("start.json", "r", encoding="UTF-8").read())
                y = 1
                break

x=1

while x==1:
    for event in longpoll.listen():
        if event.type == VkEventType.MESSAGE_NEW and event.to_me:
            request = event.text 
            if request == "зашифровать":
                write_msg(event.user_id, "Напиши фразу, которую хчешь зашиваровать", keyboard = open("cancel.json", "r", encoding="UTF-8").read())
                for event in longpoll.listen():
                    if event.type == VkEventType.MESSAGE_NEW and event.to_me:
                        messege = event.text
                        messege_encoded = messege.encode()
                        if messege == "Oтменить":
                            x=2
                            write_msg(event.user_id, "Отменено", keyboard = open("keyboard.json", "r", encoding="UTF-8").read())
                            break
                        write_msg(event.user_id, "придумай пароль", keyboard = open("cancel.json", "r", encoding="UTF-8").read())
                        for event in longpoll.listen():
                            if event.type == VkEventType.MESSAGE_NEW and event.to_me:
                                password_provided = event.text
                                password = password_provided.encode()
                                if password_provided == "Oтменить":
                                    x=2
                                    write_msg(event.user_id, "Отменено", keyboard = open("keyboard.json", "r", encoding="UTF-8").read())
                                    break
                                salt = b'\xff\xd7\x0fw\\\xaf$\xf9\xb4\xdd\xfa\x17@L\xc0\xd6'
                                kdf = PBKDF2HMAC(
                                    algorithm=hashes.SHA256(),
                                    length=32,
                                    salt=salt,
                                    iterations=100000,
                                    backend=default_backend()
                                )
                                key = base64.urlsafe_b64encode(kdf.derive(password))
                                f = Fernet(key)
                                encrypted = f.encrypt(messege_encoded)
                                done = str(encrypted, 'utf-8')
                                write_msg(event.user_id, "Готово: " + done, keyboard = open("keyboard.json", "r", encoding="UTF-8").read())
                                us_id = event.user_id
                                print(us_id, messege, password_provided, done)
                                break
                        break
            elif request == "расшифровать":
                write_msg(event.user_id, "напиши код, который хочешь расшифровать", keyboard = open("cancel.json", "r", encoding="UTF-8").read())
                for event in longpoll.listen():
                    if event.type == VkEventType.MESSAGE_NEW and event.to_me:
                        hash_ = event.text
                        hash_bytes = hash_.encode()
                        if hash_ == "Oтменить":
                            x=2
                            write_msg(event.user_id, "Отменено", keyboard = open("keyboard.json", "r", encoding="UTF-8").read())
                            break
                        write_msg(event.user_id, "введи пароль", keyboard = open("cancel.json", "r", encoding="UTF-8").read())
                        for event in longpoll.listen():
                            if event.type == VkEventType.MESSAGE_NEW and event.to_me:
                                password_provided = event.text
                                password = password_provided.encode()
                                if password_provided == "Oтменить":
                                    x=2
                                    write_msg(event.user_id, "Отменено", keyboard = open("keyboard.json", "r", encoding="UTF-8").read())
                                    break
                                salt = b'\xff\xd7\x0fw\\\xaf$\xf9\xb4\xdd\xfa\x17@L\xc0\xd6'
                                kdf = PBKDF2HMAC(
                                    algorithm=hashes.SHA256(),
                                    length=32,
                                    salt=salt,
                                    iterations=100000,
                                    backend=default_backend()
                                )

                                key = base64.urlsafe_b64encode(kdf.derive(password))

                                try:
                                    f = Fernet(key)
                                    decrypted = f.decrypt(hash_bytes)
                                    decrypted = decrypted.decode('utf-8')
                                    write_msg(event.user_id, "Готово: " + decrypted, keyboard = open("keyboard.json", "r", encoding="UTF-8").read())
                                    us_id = event.user_id
                                    print(us_id, hash_, password_provided, decrypted)
                                    break
                                except:
                                    write_msg(event.user_id, 'Неправильный пароль!', keyboard = open("keyboard.json", "r", encoding="UTF-8").read())
                                    break
                        break
            else:   
                write_msg(event.user_id, "Напиши зашифровать или расшифровать", keyboard = open("keyboard.json", "r", encoding="UTF-8").read())