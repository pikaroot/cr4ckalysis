#!/usr/bin/env python3
# coding: utf-8

# ------------------------------------------ LIBRARIES ------------------------------------------- #
import datetime as dt
from colorama import Fore, Style

# --------------------------------------- GLOBAL VARIABLES --------------------------------------- #
__ls__= ['set_wlist', 'set_wlist2', 'set_ipv4', 'set_uname', 'set_pword', 'set_hmode']

rst = f"{Fore.WHITE}{Style.NORMAL}"
bred = f"{Fore.RED}{Style.BRIGHT}"
grn = f"{Fore.GREEN}{Style.NORMAL}"
bgrn = f"{Fore.GREEN}{Style.BRIGHT}"
blue = f"{Fore.BLUE}{Style.BRIGHT}"

# -------------------------------------------- MANUAL -------------------------------------------- #
class FullManual:

    def manual(self):
        manual = f"""\nCR4RKALYSIS - An interactive shell for password analysis and password cracking\n
{bgrn}COMMON USES
        
        {grn}HASH CRACK{rst}
        cr4ckalysis> analyse [hash/hashfile.txt]
        cr4ckalysis> set_hmode [hmode]
        cr4ckalysis> crack [hash] [wordlist/wordlist2]

        {grn}SSH/FTP CRACK{rst}
        cr4ckalysis> set_ipv4 [xxx.xxx.xxx.xxx]
        cr4ckalysis> set_uname [string/userlist.txt]
        cr4ckalysis> set_pword [string/passlist.txt]
        cr4ckalysis> crack ipv4 [ssh/ftp]

{bgrn}AVAILABLE COMMANDS{rst}\n
        analyse...: analyse possible hash algorithms of a string or file. 
        clear.....: clear screen.
        crack.....: various functions including hash crack, SSH crack, and FTP crack.
        exit......: exit system.
        help......: display user manual.
        ls........: list settings.
        set_wlist.: set wordlist (default is ./wordlists/rockyou.txt).
        set_wlist2: set an additional wordlist.
        set_ipv4..: set listening host IP address.
        set_uname.: set a username or userlist.
        set_pword.: set a password or passlist.
        set_hmode.: set a hash algorithm.

{bgrn}HASH COVERAGE{rst}\n
        {grn}analyse{rst}
        md5, md4, md2
        sha1, sha1_crypt
        sha224, sha256, sha384, sha512
        sha3_224, sha3_256, sha3_384, sha3_512
        shake_128, shake_256
        blake2b, blake2s
        scrypt
        ripemd_128, ripemd_160, ripemd_256
        django (sha1, sha256, md5, bcrypt, pbkdf2-hmac)
        kerberos_5_asreq_preauth
        domain_cache_credentials (1 & 2)

        {grn}crack{rst}
        md5, md4
        sha1
        sha224, sha256, sha384, sha512
        sha3_224, sha3_256, sha3_384, sha3_512
        shake_128, shake_256
        blake2b, blake2s

{bgrn}DETAILED GUIDE\n
        {grn}set_wlist, set_wlist2{rst}
        cr4ckalysis> set_wlist ./wordlists/rockyou.txt
        cr4ckalysis> set_wlist2 /usr/share/wordlists/rockyou.txt

        NOTE: Directory root path (/) or current path (./) need to be added at the beginning 
        of the input to ensure fully readability from the system. 
        Wordlists will not be saved after the user exit the system.
        
        {grn}set_ipv4{rst}
        cr4ckalysis> set_ipv4 127.0.0.1

        NOTE: Insert an IP address that you want to listen to.

        {grn}set_uname, set_pword{rst}
        cr4ckalysis> set_uname david
        cr4ckalysis> set_uname ./unames.txt
        cr4ckalysis> set_uname /usr/share/unames.txt
        cr4ckalysis> set_pword SecurePass
        cr4ckalysis> set_pword ./pwords.txt
        cr4ckalysis> set_pword /usr/share/pwords.txt

        NOTE: Directory root path (/) or current path (./) need to be added at the beginning 
        of the input to ensure fully readability from the system. 
        Usernames and passwords will not be saved after the user exit the system.

        {grn}set_hmode{rst}
        cr4ckalysis> set_hmode md5
        cr4ckalysis> set_hmode blake2b

        NOTE: Only lowercases is acceptable.

        {grn}analyse{rst}
        cr4ckalysis> analyse 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
        cr4ckalysis> analyse ./hashes.txt

        {grn}crack{rst}
        cr4ckalysis> crack 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 wordlist
        cr4ckalysis> crack 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 wordlist2        
        cr4ckalysis> crack ipv4 ssh
        cr4ckalysis> crack ipv4 ftp

        NOTE: Ensure settings have the correct parameters before cracking.
        Ensure to have sufficient number of lines in wordlist to get better output.
        (minimum 50 words)\n"""
        print(manual)

class QuickGuide:

    def __init__(self):

        self.set0 = __ls__[0]
        self.set1 = __ls__[1]
        self.set2 = __ls__[2]
        self.set3 = __ls__[3]
        self.set4 = __ls__[4]
        self.set5 = __ls__[5]

    def quickguide(self, s):
        print(f'\n{blue}[*] {rst}QUICK GUIDE\n')
        if s in __ls__:
            if s == self.set0:
                print(f'\033[0;32mcr4ckalysis> {rst}{s} [path/to/wordlist]')
            elif s == self.set1:
                print(f'\033[0;32mcr4ckalysis> {rst}{s} [ONLINE or OFFLINE]')
            elif s == self.set2:
                print(f'\033[0;32mcr4ckalysis> {rst}{s} xxx.xxx.xxx.xxx')
            elif s == self.set3:
                print(f'\033[0;32mcr4ckalysis> {rst}{s} [input username or userlist.txt]')
            elif s == self.set4:
                print(f'\033[0;32mcr4ckalysis> {rst}{s} [input password or passlist.txt]')
            elif s == self.set5:
                print(f'\033[0;32mcr4ckalysis> {rst}{s} [insert hash algorithm]')
            else:
                print(f'{bred}[-] {rst}Invalid setting option.')
        print("\nTry 'help' for more information.\n")

    def crackqg(self):
        print(f'\n{blue}[*] {rst}QUICK GUIDE\n')
        print(f'\033[0;32mcr4ckalysis> {rst}crack [hash string/hashlist.txt] [wordlist/wordlist2]')
        print(f'\033[0;32mcr4ckalysis> {rst}crack [ipv4] [ssh/ftp]')
        print("\nTry 'help' for more information.\n")

    def analyseqg(self):
        print(f'\n{blue}[*] {rst}QUICK GUIDE\n')
        print(f'\033[0;32mcr4ckalysis> {rst}analyse [hash string/hashlist.txt]')
        print("\nTry 'help' for more information.\n")
