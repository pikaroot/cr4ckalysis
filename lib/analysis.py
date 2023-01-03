#!/usr/bin/env python3
# coding: utf-8

# ------------------------------------------ LIBRARIES ------------------------------------------- #
from collections import namedtuple
import sys, os, re, colorama
from colorama import Fore, Style

# --------------------------------------- GLOBAL VARIABLES --------------------------------------- #
Collection = namedtuple('Collection', ['regex', 'modes'])
HashAttr = namedtuple('HashAttr', ['name'])

collections = [
    Collection(
        regex=re.compile(r'^(\$md2\$)?[a-f0-9]{32}$', re.IGNORECASE),
        modes=[
            HashAttr(name='MD2')]),
    Collection(
        regex=re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE),
        modes=[
            HashAttr(name='MD5'),
            HashAttr(name='MD4'),
            HashAttr(name='LM'),
            HashAttr(name='RIPEMD-128'),
            HashAttr(name='Blake2b-128'),
            HashAttr(name='Blake2s-128')]),
    Collection(
        regex=re.compile(r'^([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?$', re.IGNORECASE),
        modes=[
            HashAttr(name='Domain Cached Credentials')]),
    Collection(
        regex=re.compile(r'^([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Domain Cached Credentials 2')]),
    Collection(
        regex=re.compile(r'^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$', re.IGNORECASE),
        modes=[
            HashAttr(name='MD5 Crypt'),
            HashAttr(name='FreeBSD MD5')]),
    Collection(
        regex=re.compile(r'^\$H\$[a-z0-9\/.]{31}$', re.IGNORECASE),
        modes=[
            HashAttr(name='phpBB v3.x'),
            HashAttr(name='Wordpress v2.6.0/2.6.1'),
            HashAttr(name="PHPass' Portable Hash")]),
    Collection(
        regex=re.compile(r'^[a-f0-9]{40}(:.+)?$', re.IGNORECASE),
        modes=[
            HashAttr(name='SHA-1'),
            HashAttr(name='RIPEMD-160'),
            HashAttr(name='Blake2b-160'),
            HashAttr(name='Blake2s-160')]),
    Collection(
        regex=re.compile(r'^[a-f0-9]{56}$', re.IGNORECASE),
        modes=[
            HashAttr(name='SHA-224'),
            HashAttr(name='SHA3-224')]),
    Collection(
        regex=re.compile(r'^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Blowfish(OpenBSD)'),
            HashAttr(name='Woltlab Burning Board 4.x'),
            HashAttr(name='bcrypt')]),
    Collection(
        regex=re.compile(r'\$bcrypt-sha256\$v=\d*\,t=\d\w*\,r=\d*\$[a-z0-9\/\.]{22}\$[a-z0-9\/\.]{31}$', re.IGNORECASE),
        modes=[
            HashAttr(name='bcrypt(SHA-256)')]),
    Collection(
        regex=re.compile(r'^[a-f0-9]{64}(:.+)?$', re.IGNORECASE),
        modes=[
            HashAttr(name='SHA-256'),
            HashAttr(name='RIPEMD-256'),
            HashAttr(name='SHA3-256'),
            HashAttr(name='Blake2b-256'),
            HashAttr(name='Blake2s-256')]),
    Collection(
        regex=re.compile(r'^[a-f0-9]{80}$', re.IGNORECASE),
        modes=[
            HashAttr(name='RIPEMD-320')]),
    Collection(
        regex=re.compile(r'^[a-f0-9]{96}$', re.IGNORECASE),
        modes=[
            HashAttr(name='SHA-384'),
            HashAttr(name='SHA3-384'),
            HashAttr(name='Blake2b-384')]),
    Collection(
        regex=re.compile(r'^[a-f0-9]{128}(:.+)?$', re.IGNORECASE),
        modes=[
            HashAttr(name='SHA-512'),
            HashAttr(name='Whirlpool'),
            HashAttr(name='SHA3-512'),
            HashAttr(name='Blake2b-512')]),
    Collection(
        regex=re.compile(r'^sha1\$[a-z0-9]+\$[a-f0-9]{40}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Django(SHA-1)')]),
    Collection(
        regex=re.compile(r'^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$', re.IGNORECASE),
        modes=[
            HashAttr(name='SHA-256 Crypt')]),
    Collection(
        regex=re.compile(r'^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$', re.IGNORECASE),
        modes=[
            HashAttr(name='SHA-512 Crypt')]),
    Collection(
        regex=re.compile(r'^sha256\$[a-z0-9]+\$[a-f0-9]{64}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Django(SHA-256)')]),
    Collection(
        regex=re.compile(r'^sha384\$[a-z0-9]+\$[a-f0-9]{96}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Django(SHA-384)')]),
    Collection(
        regex=re.compile(r'^\$(krb5pa|mskrb5)\$([0-9]{2})?\$.+\$[a-f0-9]{1,}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Kerberos 5 AS-REQ Pre-Auth')]),
    Collection(
        regex=re.compile(r'^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$', re.IGNORECASE),
        modes=[
            HashAttr(name='SHA-1 Crypt')]),
    Collection(
        regex=re.compile(r'^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$', re.IGNORECASE),
        modes=[
            HashAttr(name='PBKDF2-SHA1(Generic)')]),
    Collection(
        regex=re.compile(r'^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$', re.IGNORECASE),
        modes=[
            HashAttr(name='PBKDF2-SHA256(Generic)')]),
    Collection(
        regex=re.compile(r'^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$', re.IGNORECASE),
        modes=[
            HashAttr(name='PBKDF2-SHA512(Generic)')]),
    Collection(
        regex=re.compile(r'^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$', re.IGNORECASE),
        modes=[
            HashAttr(name='PBKDF2(Cryptacular)')]),
    Collection(
        regex=re.compile(r'^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$', re.IGNORECASE),
        modes=[
            HashAttr(name='PBKDF2(Dwayne Litzenberger)')]),
    Collection(
        regex=re.compile(r'^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Django(DES Crypt Wrapper)')]),
    Collection(
        regex=re.compile(r'^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Django(PBKDF2-HMAC-SHA256)')]),
    Collection(
        regex=re.compile(r'^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Django(PBKDF2-HMAC-SHA1)')]),
    Collection(
        regex=re.compile(r'^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Django(bcrypt)')]),
    Collection(
        regex=re.compile(r'^md5\$[a-f0-9]+\$[a-f0-9]{32}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Django(MD5)')]),
    Collection(
        regex=re.compile(r'^\{PKCS5S2\}[a-z0-9\/+]{64}$', re.IGNORECASE),
        modes=[
            HashAttr(name='PBKDF2(Atlassian)')]),
    Collection(
        regex=re.compile(r'^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$', re.IGNORECASE),
        modes=[
            HashAttr(name='scrypt')]),
    Collection(
        regex=re.compile(r'^bcrypt_sha256\$\$\d+\w+\$[0-9]+\$[\w\d\/\.+]{53}$', re.IGNORECASE),
        modes=[
            HashAttr(name='Django(bcrypt-SHA256)')]),
    Collection(
        regex=re.compile(r'^sha256[:$][0-9]+[:$][a-z0-9\/+]+[:$][a-z0-9\/+]{32,128}$', re.IGNORECASE),
        modes=[
            HashAttr(name='PBKDF2-HMAC-SHA256(PHP)')]),
]

# -------------------------------------------- ANALYSE -------------------------------------------- #
class Analyse(object):

    def __init__(self, collection=collections):
        super(Analyse, self).__init__()

        self.collections = list(collections)

    def identifyHash(self, h):
        h = h.strip()
        for collection in self.collections:
            if collection.regex.match(h):
                for mode in collection.modes:
                    yield mode

def writeResult(identified_modes, outfile):
	
    count = 0
    hashTypes = ""
    for mode in identified_modes:
        count += 1
        hashTypes += f'\033[1;32m[+] \033[0m{mode.name}\n'
    outfile.write(hashTypes)  
    if count == 0:
        outfile.write("\033[1;31m[-] \033[0mUnknown hash.\n")
    return (count > 0)

def writeResultToFile(identified_modes, outfile):

    count = 0
    hashTypes = ""
    for mode in identified_modes:
        count += 1
        hashTypes += f'[+] {mode.name}\n'
    outfile.write(hashTypes)    
    if count == 0:
        outfile.write("[-] Unknown hash.\n")
    return (count > 0)
