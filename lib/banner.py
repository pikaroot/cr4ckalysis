#!/usr/bin/env python3
# coding: utf-8

# ------------------------------------------ LIBRARIES ------------------------------------------- #
import random

# --------------------------------------- GLOBAL VARIABLES --------------------------------------- #
__color__   = ['\033[1;31m', '\033[1;32m', '\033[1;33m', '\033[1;34m', '\033[1;35m', '\033[1;36m', '\033[1;37m']

# -------------------------------------------- BANNER -------------------------------------------- #
class Banner: # DONE
    def __init__(self, version, author, github):
        self.version = version
        self.author = author
        self.github = github

    def getRandomColor(self):
        return random.choice(__color__)

    def printBanner(self):
        print(f"author: {self.author} version: {self.version}\ngithub: {self.github}")
        banner = f"""{self.getRandomColor()}┏━━━╸┏━━━┓╻   ╻┏━━━╸╻┏━━ ┏━━━┓╻   ╻   ╻┏━━━┓╻┏━━━┓
┃    ┃   ┃┃   ┃┃    ┃┃   ┃   ┃┃   ┃   ┃┃    ┃┃
┃    ┣┳━━┛┗━━━┫┃    ┣┻━━┓┣━━━┫┃   ┗━┳━┛┗━━━┓┃┗━━━┓
┗━━━╸╹┗━━╸    ╹┗━━━╸╹   ╹╹   ╹┗━━━╸ ╹  ┗━━━┛╹┗━━━┛\n"""
        print(banner)
        print("\033[1;34m[*] \033[0mDouble tab for available commands.\n")

# --------------------------------------------- END ---------------------------------------------- #