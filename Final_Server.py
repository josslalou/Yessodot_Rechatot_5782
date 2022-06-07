from hashlib import sha256
from os.path import getsize
from pydoc import ispath
from time import sleep
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
import Cryptage_final
"""
Project 2022 : Shmouel Hai Illouz 1616083 --- Yeoshua Lalou 1514010 
Name of The Project : ICMP TUNNELLING 

"""
SIZE = 1024  # i choose this size because max is 1500 has 1024 good number
my_ip = '192.168.43.20'
#PATH_a_crypter = 'C:/Users/joss/Desktop/test.txt'
#PATH_crypte = 'C:/Users/joss/Desktop/testcrypte.txt'

server_private_key = 7
p = 13
g = 11
public_server_key = pow(g, server_private_key) % p

CHOICE_OF_TYPES_TO_SEND = input("Enter the type to send : ")
if CHOICE_OF_TYPES_TO_SEND.upper() not in ["IMAGE", "AUDIO", "VIDEO", "TEXT"]:
    print("ERROR OF TYPE ! ")
else:
    CHOICE_OF_FILE_TO_SEND = input("Enter the PATH of the file :")
    if not ispath(CHOICE_OF_FILE_TO_SEND):
        print("The file doesnt exist !")
    else:
        Packet_for_encryption = Packet_N1 = Ether() / IP(dst=my_ip) / ICMP() / str(public_server_key)
        sendp(Packet_for_encryption)
        Temp_sniff1 = sniff(filter="icmp", count=2)
        Buffer0 = Temp_sniff1[1][Raw].load.decode('utf-8')
        shared_secret = pow(int(Buffer0),server_private_key)%p
        key = shared_secret
        print("The shared secret is :", shared_secret)
        if CHOICE_OF_TYPES_TO_SEND.upper() == 'IMAGE':
            print("send image ?")
            with open(CHOICE_OF_FILE_TO_SEND, 'rb') as pic:
                data = pic.read()
            lenght = len(data)
            numbers_de_packets = 0
            while lenght > 0:
                numbers_de_packets += 1
                lenght -= 1024
            Packet_N1 = Ether() / IP(dst=my_ip) / ICMP() / Cryptage_final.cryptage((str(numbers_de_packets)),key)
            Packet_N2 = Ether() / IP(dst=my_ip) / ICMP() / Cryptage_final.cryptage(CHOICE_OF_TYPES_TO_SEND.encode(),key)
            sendp(Packet_N1)
            print("number of packets send ...")
            Temp_sniff1 = sniff(filter="icmp", count=2)
            print("sniffing")
            Buffer1 = Temp_sniff1[1][Raw].load.decode('utf-8')
            print(Buffer1)
            if Buffer1 == 'Received':
                sendp(Packet_N2)
                Temp_sniff2 = sniff(filter="icmp", count=2)
                print(Temp_sniff2)
                Buffer2 = Temp_sniff2[1][Raw].load.decode('utf-8')
                print(Buffer2)
                if Buffer2 == 'Received the type':
                    print("I start to send the Image in ICMP packets")
                    Image = b''
                    lenght = len(data)
                    Numbers_Of_packets = 0
                    while lenght > 0:
                        packet = Ether() / IP(dst=my_ip) / ICMP() / data[:SIZE]
                        Image += data[:SIZE]
                        sendp(packet)
                        print(packet)
                        Numbers_Of_packets += 1
                        lenght = lenght - 1024
                        data = data.replace(data[:SIZE], b'')
                    print("count is :", Numbers_Of_packets, '\n')
                    print("The image has been send in packets ICMP successfully!\n")
        # with open(r'C:\Users\joss\PycharmProjects\ICMP_tunneling\photo_reussi2.jpeg', 'wb') as pic:
        #     pic.write(Image)
        ######## verifie que l'image se sauvegarde bien ici ##########

        if CHOICE_OF_TYPES_TO_SEND.upper() == 'VIDEO':
            with open(CHOICE_OF_FILE_TO_SEND, 'rb') as pic:
                data = pic.read()
            lenght = len(data)
            numbers_de_packets = 0
            while lenght > 0:
                numbers_de_packets += 1
                lenght -= 1024
            print(numbers_de_packets)
            Packet_N3 = Ether() / IP(dst=my_ip) / ICMP() / Cryptage_final.cryptage((str(numbers_de_packets)),key)
            Packet_N4 = Ether() / IP(dst=my_ip) / ICMP() / Cryptage_final.cryptage(CHOICE_OF_TYPES_TO_SEND.encode(),key)
            sendp(Packet_N3)
            Temp_sniff3 = sniff(filter="icmp", count=2)
            Buffer3 = Temp_sniff3[1][Raw].load.decode('utf-8')
            if Buffer3 == 'Received':
                sendp(Packet_N4)
                Temp_sniff4 = sniff(filter="icmp", count=2)
                Buffer4 = Temp_sniff4[1][Raw].load.decode('utf-8')
                if Buffer4 == 'Received the type':
                    print("I start to send the Image in ICMP packets")
                    Image = b''
                    lenght = len(data)
                    count = 0
                    while lenght > 0:
                        packet = Ether() / IP(dst=my_ip) / ICMP() / data[:SIZE]
                        Image += data[:SIZE]
                        sendp(packet)
                        count += 1
                        lenght = lenght - 1024
                        data = data.replace(data[:SIZE], b'')
                    print("count is :", count)
                    print("The video has been send in packets ICMP successfully!\n")

        if CHOICE_OF_TYPES_TO_SEND.upper() == 'TEXT':
            print("ici texte !")
            with open(CHOICE_OF_FILE_TO_SEND, "rb") as f:
                lenght = getsize(CHOICE_OF_FILE_TO_SEND)
                number_of_packets = 0
                lenght2 = lenght
                while lenght > 0:
                    number_of_packets += 1
                    lenght -= 1024
                print("number of packets is",number_of_packets)


                Packet_N5 = Ether() / IP(dst=my_ip) / ICMP() / Cryptage_final.cryptage(str(number_of_packets),(key))
                Packet_N6 = Ether() / IP(dst=my_ip) / ICMP() / Cryptage_final.cryptage(CHOICE_OF_TYPES_TO_SEND.encode(),key)
                sendp(Packet_N5)
                Temp_sniff5 = sniff(filter="icmp", count=2)
                Buffer5 = Temp_sniff5[1][Raw].load.decode('utf-8')
                if Buffer5 == 'Received':
                    sendp(Packet_N6)
                    Temp_sniff6 = sniff(filter="icmp", count=2)
                    Buffer6 = Temp_sniff6[1][Raw].load.decode('utf-8')
                    if Buffer6 == 'Received the type':
                        while lenght2 > 0:
                            packet2 = Ether() / IP(dst=my_ip) / ICMP() / Cryptage_final.cryptage(f.read(1024),key)
                            sendp(packet2)
                            lenght2 -= 1024

        if CHOICE_OF_TYPES_TO_SEND.upper() == 'AUDIO':
            with open(CHOICE_OF_FILE_TO_SEND, 'rb') as pic:
                data = pic.read()
            lenght = len(data)
            number_of_packets = 0
            while lenght > 0:
                number_of_packets += 1
                lenght -= 1024
            Packet_N7 = Ether() / IP(dst=my_ip) / ICMP() / Cryptage_final.cryptage((str(number_of_packets)),key)
            Packet_N8 = Ether() / IP(dst=my_ip) / ICMP() / Cryptage_final.cryptage(CHOICE_OF_TYPES_TO_SEND.encode(),key)
            sendp(Packet_N7)

            Temp_sniff7 = sniff(filter="icmp", count=2)
            Buffer6 = Temp_sniff7[1][Raw].load.decode('utf-8')
            if Buffer6 == 'Received':
                sendp(Packet_N8)
                Temp_sniff8 = sniff(filter="icmp", count=2)
                Buffer7 = Temp_sniff8[1][Raw].load.decode('utf-8')
                if Buffer7 == 'Received the type':
                    print("I start to send the audio in ICMP packets")
                    Image = b''
                    lenght = len(data)
                    count = 0
                    while lenght > 0:
                        packet = Ether() / IP(dst=my_ip) / ICMP() / data[:SIZE]
                        Image += data[:SIZE]
                        sendp(packet)
                        count += 1
                        lenght = lenght - 1024
                        data = data.replace(data[:SIZE], b'')
                    print("The audio has been send in packets ICMP successfully!\n")
