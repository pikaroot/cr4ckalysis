#!/usr/bin/env python3
# coding: utf-8
# Credits to jeanphorn: https://github.com/jeanphorn/wordlist 

# ------------------------------------------ LIBRARIES ------------------------------------------- #
import lib.manual, lib.crack
import sys, os, colorama, re
import glob
from colorama import Fore, Style
from cmd import Cmd
from lib.banner import *
from lib.manual import *
from lib.analysis import *
from lib.crack import *

# --------------------------------------- GLOBAL VARIABLES --------------------------------------- #
__version__ = "1.0.1"
__author__  = "pikaroot (David)"
__github__  = "https://github.com/pikaroot/cr4ckalysis"

rst = f"{Fore.WHITE}{Style.NORMAL}"
bred = f"{Fore.RED}{Style.BRIGHT}"
grn = f"{Fore.GREEN}{Style.NORMAL}"
bgrn = f"{Fore.GREEN}{Style.BRIGHT}"
blue = f"{Fore.BLUE}{Style.BRIGHT}"

# --------------------------------------- Global Function --------------------------------------- #
def _append_slash(path):
    if path and os.path.isdir(path) and path[-1] != os.sep:
        return path + os.sep
    else:
        return path

def check_ip(ip):
    flag = 0

    regex = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    zeros = re.compile(r'^0{2,3}|0[1-9][0-9]|0[1-9]|00[1-9]$')
    if regex.match(ip):
        field = ip.split(".")
        for i in range(0, len(field)):
            if (int(field[i]) < 256) and not zeros.match(field[i]):
                
                flag += 1
            else:
                flag = 0
    if flag == 4:
        return True
    else:
        return False

# ------------------------------------------- Terminal ------------------------------------------- #
class Terminal(Cmd):

    def __init__(self):

        Cmd.__init__(self)
        self.prompt = f'{grn}cr4ckalysis>{rst} '
        self.setting1 = "./wordlists/rockyou.txt"
        self.setting2 = "/usr/share/dirb/wordlists/common.txt"
        self.setting3 = "127.0.0.1" # IP address
        self.setting4 = "admin" # Username
        self.setting5 = "./passlist.txt" # Password
        self.setting6 = "MD5" # hashmode

    def get_wordlist(self): # DONE
        return self.setting1

    def get_wordlist2(self): # DONE
        return self.setting2

    def get_ipv4(self): # DONE
        return self.setting3

    def get_username(self): # DONE
        return self.setting4

    def get_password(self): # DONE
        return self.setting5

    def get_hashmode(self): # DONE
        return self.setting6

    def set_wordlist(self, setting1): # DONE
        self.setting1 = setting1

    def set_wordlist2(self, setting2): # DONE
        self.setting2 = setting2

    def set_ipv4(self, setting3): # DONE
        self.setting3 = setting3

    def set_username(self, setting4): # DONE
        self.setting4 = setting4

    def set_password(self, setting5): # DONE
        self.setting5 = setting5

    def set_hashmode(self, setting6): # DONE
        self.setting6 = setting6

    def completenames(self, text, *ignored): # DONE
        dotext = 'do_'+text
        return [a[3:]+' ' for a in self.get_names() if a.startswith(dotext)]

    def do_set_wlist(self, args): # DONE
        params = args.split()

        if len(params) == 0 or len(params) > 1:
            qg = QuickGuide()
            qg.quickguide(lib.manual.__ls__[0])

        elif os.path.isfile(params[0]):
            self.setting1 == params[0]
            self.set_wordlist(params[0])
            print(f"\n{bgrn}[+] {rst}Set wordlist --> {params[0]}")
            print(f"{bgrn}[+] {rst}Command completed successfully.\n")

        elif os.path.isdir(params[0]):
            self.stdout.write(f'\n{bred}[-] {rst}Incomplete path to file: %s\n\n' % (params[0],))
        
        else:
            self.stdout.write(f'\n{bred}[-] {rst}File not exist: %s\n\n' % (params[0],))

    def complete_set_wlist(self, text, line, begidx, endidx): # DONE
        cmdidx = line.rfind(" ", 0, begidx)
        if cmdidx == -1:
            return

        cmd = line[cmdidx+1:begidx]
        wl = line[cmdidx+1:endidx]
        pattern = wl + '*'

        complete = []
        for path in glob.glob(pattern):
            path = _append_slash(path)
            complete.append(path.replace(cmd, "", 1))
        return complete

    def do_set_wlist2(self, args): # DONE
        params = args.split()

        if len(params) == 0 or len(params) > 1:
            qg = QuickGuide()
            qg.quickguide(lib.manual.__ls__[1])

        elif os.path.isfile(params[0]):
            self.setting2 == params[0]
            self.set_wordlist2(params[0])
            print(f"\n{bgrn}[+] {rst}Set wordlist2 --> {params[0]}")
            print(f"{bgrn}[+] {rst}Command completed successfully.\n")

        elif os.path.isdir(params[0]):
            self.stdout.write(f'\n{bred}[-] {rst}Incomplete path to file: %s\n\n' % (params[0],))
        
        else:
            self.stdout.write(f'\n{bred}[-] {rst}File not exist: %s\n\n' % (params[0],))

    def complete_set_wlist2(self, text, line, begidx, endidx): # DONE
        cmdidx = line.rfind(" ", 0, begidx)
        if cmdidx == -1:
            return

        cmd = line[cmdidx+1:begidx]
        wl2 = line[cmdidx+1:endidx]
        pattern = wl2 + '*'

        complete = []
        for path in glob.glob(pattern):
            path = _append_slash(path)
            complete.append(path.replace(cmd, "", 1))
        return complete

    def do_set_hmode(self, args): # DONE
        params = args.split()

        if len(params) == 0 or len(params) > 1:
            qg = QuickGuide()
            qg.quickguide(lib.manual.__ls__[5])

        elif params[0] in lib.crack.__algorithms__:
            self.setting6 == params[0]
            self.set_hashmode(params[0].upper())
            print(f"\n{bgrn}[+] {rst}Set hashmode --> {params[0].upper()}")
            print(f"{bgrn}[+] {rst}Command completed successfully.\n")
        
        else:
            self.stdout.write(f'\n{bred}[-] {rst}Hash algorithm not support: %s\n\n' % (params[0],))

    def complete_set_hmode(self, text, line, begidx, endidx): # DONE
        if text:
            return [alg + ' ' for alg in lib.crack.__algorithms__ if alg.startswith(text)]
        else:
            return lib.crack.__algorithms__

    def do_set_uname(self, args): # DONE
        params = args.split()

        if len(params) == 0 or len(params) > 1:
            qg = QuickGuide()
            qg.quickguide(lib.manual.__ls__[3])

        elif os.path.isfile(params[0]):
            self.setting3 == params[0]
            self.set_username(params[0])
            print(f"\n{bgrn}[+] {rst}File input: {params[0]}")
            print(f"{bgrn}[+] {rst}Set username --> {params[0]}")
            print(f"{bgrn}[+] {rst}Command completed successfully.\n")

        elif os.path.isdir(params[0]):
            self.stdout.write(f'\n{bred}[-] {rst}Incomplete path to file: %s\n\n' % (params[0],))
        
        else:
            self.setting3 == params[0]
            self.set_username(params[0])
            print(f"\n{bgrn}[+] {rst}String input: {params[0]}")
            print(f"{bgrn}[+] {rst}Set username --> {params[0]}")
            print(f"{bgrn}[+] {rst}Command completed successfully.\n")

    def do_set_pword(self, args): # DONE
        params = args.split()

        if len(params) == 0 or len(params) > 1:
            qg = QuickGuide()
            qg.quickguide(lib.manual.__ls__[4])

        elif os.path.isfile(params[0]):
            self.setting4 == params[0]
            self.set_password(params[0])
            print(f"\n{bgrn}[+] {rst}File input: {params[0]}")
            print(f"{bgrn}[+] {rst}Set password --> {params[0]}")
            print(f"{bgrn}[+] {rst}Command completed successfully.\n")

        elif os.path.isdir(params[0]):
            self.stdout.write(f'\n{bred}[-] {rst}Incomplete path to file: %s\n\n' % (params[0],))
        
        elif not os.path.exists(params[0]):
            self.setting4 == params[0]
            self.set_password(params[0])
            print(f"\n{bgrn}[+] {rst}String input: {params[0]}")
            print(f"{bgrn}[+] {rst}Set password --> {params[0]}")
            print(f"{bgrn}[+] {rst}Command completed successfully.\n")
        
    def complete_set_uname(self, text, line, begidx, endidx): # DONE
        cmdidx = line.rfind(" ", 0, begidx)
        if cmdidx == -1:
            return

        cmd = line[cmdidx+1:begidx]
        ul = line[cmdidx+1:endidx]
        pattern = ul + '*'

        complete = []
        for path in glob.glob(pattern):
            path = _append_slash(path)
            complete.append(path.replace(cmd, "", 1))
        return complete

    def complete_set_pword(self, text, line, begidx, endidx): # DONE
        cmdidx = line.rfind(" ", 0, begidx)
        if cmdidx == -1:
            return

        cmd = line[cmdidx+1:begidx]
        pl = line[cmdidx+1:endidx]
        pattern = pl + '*'

        complete = []
        for path in glob.glob(pattern):
            path = _append_slash(path)
            complete.append(path.replace(cmd, "", 1))
        return complete

    def do_ls(self, args): # DONE
        if len(args) == 0:
            self.stdout.write(f'\n{blue}[*] {rst}SETTINGS\n')
            self.stdout.write(f'\nwordlist.: ' + self.get_wordlist())
            self.stdout.write(f'\nwordlist2: ' + self.get_wordlist2())
            self.stdout.write(f'\nipv4.....: ' + self.get_ipv4())
            self.stdout.write(f'\nusername.: ' + self.get_username())
            self.stdout.write(f'\npassword.: ' + self.get_password())
            self.stdout.write(f'\nhashmode.: ' + self.get_hashmode() + '\n\n')
        else:
            print(f"\n{bred}[-] {rst}Command 'ls' takes no arguments.\n")

    def do_analyse(self, args): # DONE  
        params = args.split()
        if len(params) == 0 or len(params) > 1:
            qg = QuickGuide()
            qg.analyseqg()
        else:
            hashID = Analyse()
            
            if os.path.isfile(params[0]):
                try:
                    with open(params[0], "r", encoding="latin-1") as infile:
                        self.stdout.write(f"\n{blue}[*] {rst}File '{params[0]}'\n")
                        for line in infile:
                            if line.strip():
                                self.stdout.write(f"\n{blue}[*] {rst}Analyzing '{grn}{line.strip()}{rst}'...\n")
                                lib.analysis.writeResult(hashID.identifyHash(line), self.stdout)
                except (EnvironmentError, UnicodeDecodeError):
                    self.stdout.write(f"\n{bred}[-] {rst}File '{params[0]}' could not open.\n\n")
                except KeyboardInterrupt:
                    self.stdout.write(f"\n{bred}[-] {rst}Interrupt analysis '{params[0]}'.\n\n")
                else:
                    self.stdout.write(f"\n{blue}[*] {rst}End of file '{params[0]}'.\n\n")                
            
            else:
                self.stdout.write(f"\n{blue}[*] {rst}Analyzing '{grn}{params[0]}{rst}'...\n")
                lib.analysis.writeResult(hashID.identifyHash(params[0]), self.stdout)
                self.stdout.write(f"\n{blue}[*] {rst}End of analysis.\n\n")

    def complete_analyse(self, text, line, begidx, endidx): # DONE
        cmdidx = line.rfind(" ", 0, begidx)
        if cmdidx == -1:
            return

        cmd = line[cmdidx+1:begidx]
        file = line[cmdidx+1:endidx]
        pattern = file + '*'

        complete = []
        for path in glob.glob(pattern):
            path = _append_slash(path)
            complete.append(path.replace(cmd, "", 1))
        return complete

    def do_crack(self, args):       
        params = args.split()
        if len(params) <= 1 or len(params) > 2:
            qg = QuickGuide()
            qg.crackqg()
        else:
            try:
                if params[1] == lib.crack.__crackcmd__[0]:
                    self.stdout.write(f"\n{blue}[*] {rst}hash(.txt): {params[0]}")
                    self.stdout.write(f"\n{blue}[*] {rst}hashmode: {self.get_hashmode()}")
                    self.stdout.write(f"\n{blue}[*] {rst}wordlist: {self.get_wordlist()}")
                    self.stdout.write(f"\n{bgrn}[+] {rst}cr4cking...\n")          
                    crack = Crack()
                    crack.hlcrack(params[0], self.get_hashmode(), self.get_wordlist())
                elif params[1] == lib.crack.__crackcmd__[1]:
                    self.stdout.write(f"\n{blue}[*] {rst}hash(.txt): {params[0]}")
                    self.stdout.write(f"\n{blue}[*] {rst}hashmode: {self.get_hashmode()}")
                    self.stdout.write(f"\n{blue}[*] {rst}wordlist: {self.get_wordlist2()}")
                    self.stdout.write(f"\n{bgrn}[+] {rst}cr4cking...\n")
                    crack = Crack()
                    crack.hlcrack(params[0], self.get_hashmode(), self.get_wordlist2())
                elif params[0] == "ipv4" and params[1] == "ftp":
                    ftp = Crack()
                    ftp.ftpcrack(self.get_ipv4(), self.get_username(), self.get_password())
                elif params[0] == "ipv4" and params[1] == "ssh":
                    ssh = Crack()
                    ssh.sshcrack(self.get_ipv4(), self.get_username(), self.get_password())
                else:
                    self.stdout.write(f'\n{bred}[-] {rst}Command line error. Try help for more information.\n\n')
 
            except (EnvironmentError, UnicodeDecodeError):
                self.stdout.write(f"\n{bred}[-] {rst}File '{params[0]}' could not open.\n\n")
            except KeyboardInterrupt:
                self.stdout.write(f"\n{bred}[-] {rst}Interrupt cracking '{params[0]}'.\n\n")
            except IndexError:
                self.stdout.write(f"\n{bred}[-] {rst}Please choose a wordlist.\n")
                self.stdout.write(f'{blue}[*] {rst}SETTINGS\n')
                self.stdout.write(f'\nwordlist.: ' + self.get_wordlist())
                self.stdout.write(f'\nwordlist2: ' + self.get_wordlist2() + '\n\n')
            except ValueError:
                self.stdout.write(f'\n{bred}[-] {rst}Unsupported hash type: {hashmode}\n\n')

    def complete_crack(self, text, line, begidx, endidx): # DONE
        if text:
            return [setting + ' ' for setting in lib.crack.__crackcmd__ if setting.startswith(text)]
        else:
            return lib.crack.__crackcmd__

    def do_set_ipv4(self,args): # DONE
        params = args.split()
        if len(params) == 0 or len(params) > 2:
            qg = QuickGuide()
            qg.quickguide(lib.manual.__ls__[2])
        else:
            if check_ip(params[0]):
                self.setting2 == params[0]
                self.set_ipv4(params[0])
                print(f"\n{bgrn}[+] {rst}Set ipv4 --> {params[0]}")
                print(f"{bgrn}[+] {rst}Command completed successfully.\n")
            else:
                self.stdout.write(f"\n{bred}[-] {rst}Not a valid IP address. Try 'help' for more information.\n\n")


    def do_clear(self, args): # DONE
        if len(args) == 0:
            os.system('clear')
            banner = Banner(__version__, __author__, __github__)
            banner.printBanner()
        else:
            print(f"\n{bred}[-] {rst}Command 'clear' takes no arguments.\n")

    def do_exit(self, args): # DONE
        if len(args) == 0:
            print(f'\n{blue}[*] {rst}Exiting program...')
            sys.exit()
        else:
            print(f"\n{bred}[-] {rst}Command 'exit' takes no arguments.\n")

    def do_help(self, args): # DONE
        if len(args) == 0:
            manual = FullManual()
            manual.manual()
        else:
            print(f"\n{bred}[-] {rst}Command 'help' takes no arguments.\n")

    def default(self, line): # DONE
        self.stdout.write(f'\n{bred}[-] {rst}Unknown command: %s\n\n' % (line,))

    def emptyline(self): # DONE
        return None

# --------------------------------------------- Main --------------------------------------------- #
def main():
    banner = Banner(__version__, __author__, __github__)
    banner.printBanner()

    try:
        cmd = Terminal()
        cmd.cmdloop()

    except KeyboardInterrupt:
        print(f"\n\n{blue}[*] {rst}Keyboard Interrupt. Exiting program...")
        sys.exit()

if __name__ == "__main__":
    main()
