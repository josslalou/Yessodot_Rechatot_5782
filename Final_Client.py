from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether

import Cryptage_final

my_ip = '192.168.43.6'


def main():
    print("Welcome to the J&N ICMP route !")
    print("The reception is connected ")
    # key = input("enter the key: ")
    print("waiting ....")
    client_private_key = 6
    p = 13
    g = 11
    public_client_key = pow(g, client_private_key) % p

    Temp_sniff0 = sniff(filter="icmp", count=2)
    Buffer0 = Temp_sniff0[0][Raw].load

    shared_secret = pow(int(Buffer0), client_private_key) % p
    Packet_N0 = Ether() / IP(dst=my_ip) / ICMP() / str(public_client_key)
    sendp(Packet_N0)
    key = shared_secret
    print("the shared key is ", key)

    Temp_sniff1 = sniff(filter="icmp", count=2)
    Buffer1 = Temp_sniff1[1][Raw].load

    print(Buffer1)
    temp = Cryptage_final.cryptage(Buffer1, int(key))
    print(temp)
    var_int = int(temp)
    print("The number of ICMP packets is:", var_int)
    Packet_N1 = Ether() / IP(dst=my_ip) / ICMP() / 'Received'
    sendp(Packet_N1)
    Temp_sniff2 = sniff(filter="icmp", count=3)
    print(Temp_sniff2)
    temp = Temp_sniff2[2][ICMP].load
    print(temp)
    type_du_packet = Cryptage_final.cryptage(temp, key)
    Packet_N2 = Ether() / IP(dst=my_ip) / ICMP() / 'Received the type'
    sendp(Packet_N2)
    print("The type of the packet is :", type_du_packet)
    print(type_du_packet)
    """""""""possibility of Types"""""

    if type_du_packet.decode().upper() == 'TEXT':
        Buffer2 = b''
        Temp_sniff3 = sniff(filter="icmp", count=var_int * 2)
        for i in range(var_int * 2):
            if i % 2 != 0:
                Buffer2 += Cryptage_final.cryptage(Temp_sniff3[i][Raw].load, key)
        with open(r'C:\Users\joss\PycharmProjects\ICMP_tunneling\testText.txt', 'wb') as pic:
            pic.write(Buffer2)

    elif type_du_packet.decode().upper() == 'IMAGE':
        Buffer3 = b''
        Temp_sniff4 = sniff(filter="icmp", count=var_int * 2)
        for i in range(var_int * 2):
            if i % 2 != 0:
                Buffer3 += Temp_sniff4[i][Raw].load
        with open(r'C:\Users\joss\PycharmProjects\ICMP_tunneling\crack.jpg', 'wb') as pic:
            pic.write(Buffer3)

    elif type_du_packet.decode().upper() == 'VIDEO':
        Buffer4 = b''
        Temp_sniff5 = sniff(filter="icmp", count=var_int * 2)
        for i in range(var_int * 2):
            if i % 2 != 0:
                Buffer4 += Temp_sniff5[i][Raw].load
        with open(r'C:\Users\joss\PycharmProjects\ICMP_tunneling\hacktest26.mp4', 'wb') as pic:
            pic.write(Buffer4)

    elif type_du_packet.decode().upper() == 'AUDIO':
        Buffer5 = b''
        Temp_sniff6 = sniff(filter="icmp", count=var_int * 2)
        for i in range(var_int * 2):
            if i % 2 != 0:
                Buffer5 += Temp_sniff6[i][Raw].load
        with open(r'C:\Users\joss\PycharmProjects\ICMP_tunneling\test_audio.mp3', 'wb') as pic:
            pic.write(Buffer5)


if __name__ == "__main__":
    main()
