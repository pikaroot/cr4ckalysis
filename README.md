# ***cr4ckalysis***

![Kali](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/python_3.10-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

Cr4ckalysis is an interactive shell for hash analysis and password recovery in Python.<br>
**Project In Progression**

## Features

- Hash Analysis
- SSH Password Cracking
- FTP Password Cracking
- Offline Hash Recovery
- Parameter Settings

## Requirements

### Install latest python3, pexpect
```
sudo apt update
sudo apt install python3
pip3 install pexpect
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
chmod +x cr4ckalysis
./cr4ckalysis
```

## Hash Coverage

| ***Hash Algorithm*** | ***Description***                              |
|----------------------|------------------------------------------------|
| MD5                  | Message-Digest Algorithm 5                     |
| MD4                  | Message-Digest Algorithm 4                     |
| SHA-1                | Secure Hash Algorithm 1                        |
| SHA-224              | Secure Hash Algorithm 2 with 224 bits          |
| SHA-256              | Secure Hash Algorithm 2 with 256 bits          |
| SHA-384              | Secure Hash Algorithm 2 with 384 bits          |
| SHA-512              | Secure Hash Algorithm 2 with 512 bits          |
| SHA3-224             | Secure Hash Algorithm 3 with 224 bits          |
| SHA3-256             | Secure Hash Algorithm 3 with 256 bits          |
| SHA3-384             | Secure Hash Algorithm 3 with 384 bits          |
| SHA3-512             | Secure Hash Algorithm 3 with 512 bits          |
| SHAKE-128            | Shake 128 bits                                 |
| SHAKE-256            | Shake 256 bits                                 |
| BLAKE2b              | Blake 2 (1-64 bits)                            |
| BLAKE2s              | Blake 2 (1-32 bits)                            |

## Similar Tools

- [Hashcat](https://github.com/hashcat/hashcat)
- [John](https://github.com/openwall/john)
- [THC-HYDRA](https://github.com/vanhauser-thc/thc-hydra)
- [Pydictor](https://github.com/LandGrey/pydictor)
