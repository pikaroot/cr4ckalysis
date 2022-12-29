# ***cr4ckalysis***

![Kali](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/python_3.10-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

Cr4ckalysis is an interactive shell for hash analysis and password recovery in Python.<br>

## Features

- Hash Analysis
- SSH Password Cracking
- FTP Password Cracking
- Offline Hash Recovery
- Parameter Settings

## Limitations

- `Wordlists` used must contain at least 50 words in order to function properly (For SSH and FTP cracking).
- When inserting `file` as parameter, the root `/` or current `./` must include at the front of the file for better performance.
- Limited hash algorithms (based on NIST framework policy) are supported in hash analysis and recovery.
- End users cannot modify the thread counts as it will affect the stability of the system. `default threads = 30`

## Requirements

### Install latest python3, pexpect, ftplib, python-nmap
```
sudo apt update
sudo apt install python3
pip3 install pexpect
pip3 install ftplib
pip3 install python-nmap
```

### Install rockyou.txt

Download here [rockyou.txt.gz](https://github.com/praetorian-inc/Hob0Rules/blob/master/wordlists/rockyou.txt.gz)
```
gunzip rockyou.txt.gz
mv rockyou.txt ~/cr4ckalysis/wordlists
```

<!--### Install cr4ckalysis
```sudo apt install cr4ckalysis
cr4ckalysis
```
-->

## Installation

### Clone git repository
```
git clone https://github.com/pikaroot/cr4ckalysis.git
cd cr4ckalysis
chmod +x cr4ckalysis.py
./cr4ckalysis.py
```

## Hash Coverage

| ***Hash Algorithm*** | ***Description***                              | ***Available Commands*** |
|----------------------|------------------------------------------------|--------------------------|
| MD5                  | Message-Digest Algorithm 5                     | `analyse` `crack`        |
| MD4                  | Message-Digest Algorithm 4                     | `analyse` `crack`        |
| SHA-1                | Secure Hash Algorithm 1                        | `analyse` `crack`        |
| SHA-224              | Secure Hash Algorithm 2 with 224 bits          | `analyse` `crack`        |
| SHA-256              | Secure Hash Algorithm 2 with 256 bits          | `analyse` `crack`        |
| SHA-384              | Secure Hash Algorithm 2 with 384 bits          | `analyse` `crack`        |
| SHA-512              | Secure Hash Algorithm 2 with 512 bits          | `analyse` `crack`        |
| SHA3-224             | Secure Hash Algorithm 3 with 224 bits          | `analyse` `crack`        |
| SHA3-256             | Secure Hash Algorithm 3 with 256 bits          | `analyse` `crack`        |
| SHA3-384             | Secure Hash Algorithm 3 with 384 bits          | `analyse` `crack`        |
| SHA3-512             | Secure Hash Algorithm 3 with 512 bits          | `analyse` `crack`        |
| SHAKE-128            | Shake 128 bits                                 | `analyse` `crack`        |
| SHAKE-256            | Shake 256 bits                                 | `analyse` `crack`        |
| BLAKE2b              | Blake 2b (128, 160, 256, 384, 512) bits        | `analyse` `crack`        |
| BLAKE2s              | Blake 2 (128, 160, 256) bits                   | `analyse` `crack`        |

## User Guide

### System Banner

```
author: pikaroot (David) version: 1.0.1                                                      
github: https://github.com/pikaroot/cr4ckalysis                                              
┏━━━╸┏━━━┓╻   ╻┏━━━╸╻┏━━ ┏━━━┓╻   ╻   ╻┏━━━┓╻┏━━━┓                                           
┃    ┃   ┃┃   ┃┃    ┃┃   ┃   ┃┃   ┃   ┃┃    ┃┃                                               
┃    ┣┳━━┛┗━━━┫┃    ┣┻━━┓┣━━━┫┃   ┗━┳━┛┗━━━┓┃┗━━━┓                                           
┗━━━╸╹┗━━╸    ╹┗━━━╸╹   ╹╹   ╹┗━━━╸ ╹  ┗━━━┛╹┗━━━┛                                           
                                                                                             
[*] Double tab for available commands.                                                       
                                                                                             
cr4ckalysis>
```
### User Man Page

```
cr4ckalysis> help

CR4RKALYSIS - An interactive shell for password analysis and password cracking

COMMON USES
        
        HASH CRACK
        cr4ckalysis> analyse [hash/hashfile.txt]
        cr4ckalysis> set_hmode [hmode]
        cr4ckalysis> crack [hash] [wordlist/wordlist2]

        SSH/FTP CRACK
        cr4ckalysis> set_ipv4 [xxx.xxx.xxx.xxx]
        cr4ckalysis> set_uname [string/userlist.txt]
        cr4ckalysis> set_pword [string/passlist.txt]
        cr4ckalysis> crack ipv4 [ssh/ftp]

AVAILABLE COMMANDS
                                                                                             
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
                                                                                             
HASH COVERAGE                                                                                
                                                                                             
        analyse                                                                              
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
                                                                                             
        crack                                                                                
        md5, md4                                                                             
        sha1                                                                                 
        sha224, sha256, sha384, sha512                                                       
        sha3_224, sha3_256, sha3_384, sha3_512                                               
        shake_128, shake_256                                                                 
        blake2b, blake2s                                                                     
                                                                                             
DETAILED GUIDE                                                                               
                                                                                             
        set_wlist, set_wlist2                                                                
        cr4ckalysis> set_wlist ./wordlists/rockyou.txt                                       
        cr4ckalysis> set_wlist2 /usr/share/wordlists/rockyou.txt                             
                                                                                             
        NOTE: Directory root path (/) or current path (./) need to be added at the beginning 
        of the input to ensure fully readability from the system.                            
        Wordlists will not be saved after the user exit the system.                          
                                                                                             
        set_ipv4                                                                             
        cr4ckalysis> set_ipv4 127.0.0.1                                                      
                                                                                             
        NOTE: Insert an IP address that you want to listen to.                               
                                                                                             
        set_uname, set_pword                                                                 
        cr4ckalysis> set_uname david                                                         
        cr4ckalysis> set_uname ./unames.txt                                                  
        cr4ckalysis> set_uname /usr/share/unames.txt                                         
        cr4ckalysis> set_pword SecurePass                                                    
        cr4ckalysis> set_pword ./pwords.txt                                                  
        cr4ckalysis> set_pword /usr/share/pwords.txt                                         
                                                                                             
        NOTE: Directory root path (/) or current path (./) need to be added at the beginning 
        of the input to ensure fully readability from the system.                            
        Usernames and passwords will not be saved after the user exit the system.            
                                                                                             
        set_hmode                                                                            
        cr4ckalysis> set_hmode md5                                                           
        cr4ckalysis> set_hmode blake2b                                                       
                                                                                             
        NOTE: Only lowercases is acceptable.                                                 
                                                                                             
        analyse                                                                              
        cr4ckalysis> analyse 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8                        
        cr4ckalysis> analyse ./hashes.txt                                                    
                                                                                             
        crack                                                                                
        cr4ckalysis> crack 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 wordlist                 
        cr4ckalysis> crack 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 wordlist2                
        cr4ckalysis> crack ipv4 ssh                                                          
        cr4ckalysis> crack ipv4 ftp                                                          
                                                                                             
        NOTE: Ensure settings have the correct parameters before cracking.                   
        Ensure to have sufficient number of lines in wordlist to get better output.          
        (minimum 50 words)
```
### Parameter Settings

Every parameter in the settings function are modifiable based on users' situation.
```
cr4ckalysis> ls                                                                              
                                                                                             
[*] SETTINGS                                                                                 
                                                                                             
wordlist.: ./wordlists/rockyou.txt                                                           
wordlist2: /usr/share/dirb/wordlists/common.txt                                              
ipv4.....: 127.0.0.1                                                                         
username.: admin                                                                             
password.: ./testpass.txt                                                                    
hashmode.: MD5
```
### Hash Analysis
The system can recognize and analyse respectable amount of hash algorithms based on user input.
```
cr4ckalysis> analyse ./testhashes.txt                                                        
                                                                                             
[*] File './testhashes.txt'                                                                  
                                                                                             
[*] Analyzing '8eac4ee0790850314134f837b47dfd56'...                                          
[+] MD2                                                                                      
[+] MD5                                                                                      
[+] MD4                                                                                      
[+] LM                                                                                       
[+] RIPEMD-128                                                                               
[+] Blake2b-128                                                                              
[+] Blake2s-128                                                                              
[+] Domain Cached Credentials                                                                
[+] Domain Cached Credentials 2                                                              
                                                                                             
[*] Analyzing '$2a$08$VPzNKPAY60FsAbnq.c.h5.XTCZtC1z.j3hnlDFGImN9FcpfR1QnLq'...              
[+] Blowfish(OpenBSD)                                                                        
[+] Woltlab Burning Board 4.x
[+] bcrypt

[*] Analyzing 'b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3'...
[+] SHA-1                                                                                    
[+] RIPEMD-160
[+] Blake2b-160
[+] Blake2s-160

[*] Analyzing 'adfb6dd1ab1238afc37acd8ca24c1279f8d46f61907dd842faab35b0cc41c6e8ad84cbdbef4964b8334c22c4985c2387d53bc47e6c3d0940ac962f521a127d9f'...                                       
[+] SHA-512                                                                                  
[+] Whirlpool
[+] SHA3-512
[+] Blake2b-512

[*] Analyzing '1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032'...
[+] SHA-256                                                                                  
[+] RIPEMD-256
[+] SHA3-256
[+] Blake2b-256
[+] Blake2s-256

[*] Analyzing '52690d7a185168de52d1e7271df62ac2f1c6275967942ff1198eeb957ec669ff9a17079eeeac663bb063ca6d3e4f6bff'...                                                                       
[+] SHA-384                                                                                  
[+] SHA3-384
[+] Blake2b-384

[*] Analyzing '$bcrypt-sha256$v=2,t=2b,r=12$n79VH.0Q2TMWmt3Oqt9uku$Kq4Noyk3094Y2QlB8NdRT8SvGiI4ft2'...                                                                                    
[+] bcrypt(SHA-256)                                                                          

[*] Analyzing '$bcrypt-sha256$v=2,t=2b,r=13$AmytCA45b12VeVg0YdDT3.$IZTbbJKgJlD5IJoCWhuDUqYjnJwNPlO'...                                                                                    
[+] bcrypt(SHA-256)                                                                          

[*] Analyzing '$pbkdf2-sha256$29000$w5hzDiHkHEMoxZiTEiLkPA$JVlYyyek5oc0CV.zayIisaW9Mncl7OYnEs49S.vKtLg'...                                                                                
[+] PBKDF2-SHA256(Generic)                                                                   

[*] Analyzing 'bcrypt_sha256$$2b$12$QeWvpi7hQ8cPQBF0LzD4C.89R81AV4PxK0kjVXG73fkLoQxYBundW'...
[+] Django(bcrypt-SHA256)                                                                    

[*] Analyzing 'pbkdf2_sha256$20000$DS20ZOCWTBFN$AFfzg3iC24Pkj5UtEu3O+J8KOVBQvaLVx43D0Wsr4PY='...                                                                                          
[+] Django(PBKDF2-HMAC-SHA256)                                                               

[*] Analyzing '$krb5pa$23$user$realm$salt$4e751db65422b2117f7eac7b721932dc8aa0d9966785ecd958f971f622bf5c42dc0c70b532363138363631363132333238383835'...                                    
[+] Kerberos 5 AS-REQ Pre-Auth                                                               

[*] Analyzing '$mskrb5$$$98cd00b6f222d1d34e08fe0823196e0b$5937503ec29e3ce4e94a051632d0fff7b6781f93e3decf7dca707340239300d602932154'...                                                    
[+] Kerberos 5 AS-REQ Pre-Auth                                                               

[*] Analyzing 'fb611de45b88433d9f4dd604c90e9a2fc1be1843'...
[+] SHA-1                                                                                    
[+] RIPEMD-160
[+] Blake2b-160
[+] Blake2s-160

[*] Analyzing '593b743b207e10ff55ec63e71a46c07909d0880a'...
[+] SHA-1                                                                                    
[+] RIPEMD-160
[+] Blake2b-160
[+] Blake2s-160

[*] Analyzing '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'...
[+] SHA-1                                                                                    
[+] RIPEMD-160
[+] Blake2b-160
[+] Blake2s-160

[*] Analyzing 'ce3fc53fddd6db373370b9e74af93360'...
[+] MD2                                                                                      
[+] MD5
[+] MD4
[+] LM
[+] RIPEMD-128
[+] Blake2b-128
[+] Blake2s-128
[+] Domain Cached Credentials
[+] Domain Cached Credentials 2

[*] End of file './testhashes.txt'.
```

### General Hash Cracking

In general hash cracking, the `wordlist`, `wordlist2`, and `hashmode` are the parameters that affect the results. Users can insert their own wordlists to depends on their situation. Users can recover the hash by using `crack <hash> <wordlist/wordlist2>` or `crack <file> <wordlist/wordlist2>` after hash analysis.
<br>
![image](https://user-images.githubusercontent.com/107750005/209805220-9c9e59a3-820f-4924-87ba-3f5ad830da87.png)

### SSH Credential Recovery

There are three parameters that need to be set for SSH crack which are `ipv4`, `username`, and `password`.
- `set_ipv4` to the victim's IP address.
- `set_uname` to a username (if known) or a username file.
- `set_pword` to a password (if known) or a password file.

```
cr4ckalysis> set_ipv4 192.168.25.142                                                         
                                                                                             
[+] Set ipv4 --> 192.168.25.142                                                              
[+] Command completed successfully.                                                          
                                                                                             
cr4ckalysis> set_uname tommy                                                                 
                                                                                             
[+] String input: tommy                                                                      
[+] Set username --> tommy                                                                   
[+] Command completed successfully.                                                          
                                                                                             
cr4ckalysis> set_pword ./testpass.txt                                                        
                                                                                             
[+] File input: ./testpass.txt                                                               
[+] Set password --> ./testpass.txt                                                          
[+] Command completed successfully.                                                          
```
Now, we can sufficient information to crack SSH credentials by using command `crack ipv4 ssh`.
```
cr4ckalysis> crack ipv4 ssh                                               
                                                                          
[*] Checking SSH port state on: 192.168.25.142                            
[+] SSH status on 192.168.25.142: active (running)                        
[+] Connection successful.                                                
[+] Loading username: tommy                                               
[+] Loading passlist: ./testpass.txt                                      
[*] Testing combination (u:p): tommy:password                             
[*] Testing combination (u:p): tommy:password1                            
[*] Testing combination (u:p): tommy:password12                           
[*] Testing combination (u:p): tommy:password2                            
[*] Testing combination (u:p): tommy:password123                          
[*] Testing combination (u:p): tommy:password4                            
[*] Testing combination (u:p): tommy:password133                          
[*] Testing combination (u:p): tommy:password231                          
[*] Testing combination (u:p): tommy:password21                           
[*] Testing combination (u:p): tommy:password1233                         
[*] Testing combination (u:p): tommy:password1234                         
[*] Testing combination (u:p): tommy:password321                          
[*] Testing combination (u:p): tommy:Password123                          
[*] Testing combination (u:p): tommy:Password1                            
[*] Testing combination (u:p): tommy:Password                             
[*] Testing combination (u:p): tommy:Password12                           
[*] Testing combination (u:p): tommy:P@ssword                             
[*] Testing combination (u:p): tommy:P@ssw0rd                             
[*] Testing combination (u:p): tommy:p@ssw0rd                             
[*] Testing combination (u:p): tommy:p@$$w0rd                             
[*] Testing combination (u:p): tommy:p@s$w0rd                             
[*] Testing combination (u:p): tommy:Pa$$w0rd                             
[*] Testing combination (u:p): tommy:P@ssword123                          
[*] Testing combination (u:p): tommy:passpass                             
[*] Testing combination (u:p): tommy:mypass123                            
[*] Testing combination (u:p): tommy:MyPass123                            
[*] Testing combination (u:p): tommy:123password                          
[*] Testing combination (u:p): tommy:12password                           
[*] Testing combination (u:p): tommy:1password                            
[*] Testing combination (u:p): tommy:1pass                                
[*] Testing combination (u:p): tommy:Password!                            
[*] Testing combination (u:p): tommy:password!                            
[*] Testing combination (u:p): tommy:passw0rd!!                           
[*] Testing combination (u:p): tommy:password!!                           
[*] Testing combination (u:p): tommy:p@ssword!                            
[*] Testing combination (u:p): tommy:P@s$w0rd!                            
[+] Valid credentials found.    [USER]:tommy    [PASS]:password123        
[*] Testing combination (u:p): tommy:password12345                        
[*] Process ended.
```
![image](https://user-images.githubusercontent.com/107750005/209809054-be1a0e42-d988-461e-bdc3-17d522e1ffdb.png)

### FTP Credentials Recovery

Same as SSH, FTP cracking also require the identical parameters. This time, we also can brute force both `username` and `password` if none of the credentials are known. Hence, using `set_uname`, modify to a file full of usernames.
```
cr4ckalysis> ls                                                           
                                                                          
[*] SETTINGS                                                              
                                                                          
wordlist.: ./wordlists/rockyou.txt                                        
wordlist2: /usr/share/dirb/wordlists/common.txt                           
ipv4.....: 192.168.25.142                                                 
username.: tommy                                                          
password.: ./testpass.txt                                                 
hashmode.: SHA1                                                           
                                                                          
cr4ckalysis> set_uname ./testusers.txt                                    
                                                                          
[+] File input: ./testusers.txt                                           
[+] Set username --> ./testusers.txt                                      
[+] Command completed successfully.
```
Now, using command `crack ipv4 ftp` to crack.
```
cr4ckalysis> crack ipv4 ftp                                               
                                                                          
[*] Checking FTP port state on: 192.168.25.142                            
[+] FTP status on 192.168.25.142: active (running)                        
[+] Connection successful.                                                
[+] Loading userlist: ./testusers.txt                                     
[+] Loading passlist: ./testpass.txt                                      
[*] Testing combination (u:p): hammond:password                           
[*] Testing combination (u:p): hammond:password1                          
[*] Testing combination (u:p): hammond:password12                         
[*] Testing combination (u:p): hammond:password2                          
------------------<263 lines>------------------                             
[*] Testing combination (u:p): jane:password!                             
[*] Testing combination (u:p): jane:passw0rd!!                            
[*] Testing combination (u:p): jane:password!!                            
[+] Valid credentials found.    [USER]:jane     [PASS]:123password        
[*] Testing combination (u:p): jane:p@ssword!                             
[*] Process ended.
```
![image](https://user-images.githubusercontent.com/107750005/209806090-b4d97662-7cae-452b-a270-fac475bae75f.png)

## Similar Tools

- [Hashcat](https://github.com/hashcat/hashcat)
- [John](https://github.com/openwall/john)
- [THC-HYDRA](https://github.com/vanhauser-thc/thc-hydra)
- [Pydictor](https://github.com/LandGrey/pydictor)
