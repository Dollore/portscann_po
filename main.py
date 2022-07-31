import argparse
import socket
from sys import exit
import ipaddress
from os import system

# pobieranie argumentów oraz filtr
input_parse = argparse.ArgumentParser(description='takes the ip address')
input_parse.add_argument('ipaddress', metavar='ipaddress', type=str, help='Put in address ip you want to scann')
input_parse.add_argument('maska', metavar='maska', type=str, help='Put in your netmask eg.: 24 or 255.255.255.255')
input_parse.add_argument('-s', '--speed', action='store_true', default=False, help='Put -s to quick scann 0-10000 port')
input_parse.add_argument('-tA', '--all', metavar='all', action='store_const', const=1, help='Scann all ports types')
input_parse.add_argument('-tT', '--tcp', metavar='tcp', action='store_const', const=2, help='Scann tcp ports types')
input_parse.add_argument('-tU', '--udp', metavar='tcp', action='store_const', const=3, help='Scann tcp ports types')

# Przypisywanie argumentów do zmiennych
args = input_parse.parse_args()
ip = args.ipaddress
maska = args.maska
parametr = bool(args.speed)
typ = args.all or args.tcp or args.udp

print('Twoj input: ' + ip + " Maska: " + maska + " Parametr s: " + str(parametr) + " Typ: " + str(typ))


def chose_ip():
    try:
        siec = ip + chr(47) + maska
        test_sieci = ipaddress.ip_network(siec)
        lista_adresow = list(test_sieci.hosts())
        # print(test_sieci)
        # print(test_sieci.num_addresses)
        liczba_adresow = test_sieci.num_addresses
        liczba_adresow = liczba_adresow - 2
        # print(lista_adresow)
        return lista_adresow, liczba_adresow
    except ValueError:
        print('Podaj poprawny addres ip lub maskę')
        exit()


lista_adresow_x, liczba_adresow_y = chose_ip()
print('Liczba adresów: '+str(liczba_adresow_y))


def scann_sockets():
    for x in range(liczba_adresow_y):
        sorted_ip = lista_adresow_x[x]
        ping_check = system("ping -q -W 300 -c 4 "+str(sorted_ip))

        if ping_check != 0:
            print("Host {} not online".format(sorted_ip))
        else:  # parametr s lub brak
            if parametr:
                # true
                print('short scann')
                for port in range(1, 10000):
                    # TCP
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket.setdefaulttimeout(1)
                    result = s.connect_ex((str(sorted_ip), port))
                    if result == 0:
                        print("Port tcp {} is open".format(port))
                    s.close()

                    # UDP
                    # try:
                    #    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    #    u.sendto(b'Hello UDP', (str(sorted_ip), port))
                    #    u.setsockopt(socket.IPPROTO_IP, IN.IP_RECVERR, 1)
                    # except TimeoutError:
                    #    pass
                    # else:
                    #    print(ur)

            else:
                print('full scan')
                for port in range(1, 65535):
                    # TCP
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket.setdefaulttimeout(1)
                    result = s.connect_ex((str(sorted_ip), port))
                    if result == 0:
                        print("Port tcp {} is open".format(port))
                    s.close()


chose_ip()
scann_sockets()
