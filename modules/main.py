#!/usr/bin/env python3
from colorama import init, Fore, Style
init(convert=True)

banner = Fore.GREEN + Style.BRIGHT + """
          ____ _           _ _       _____             
         / ___| |__   __ _| | |___  |  ___| __ __ _  ___ _ __ 
        | |   | '_ \\ / _` | | / __| | |_ | '__/ _` |/ _ \\ '__|
        | |___| | | | (_| | | \\__ \\ |  _|| | | (_| |  __/ |   
         \\____|_| |_|\\__,_|_|_|___/ |_|  |_|  \\__, |\\___|_|   
                                              |___/         v2
        Ethical pentest beast • Built by Utah Viking • From ranch grit to root access
""" + Style.RESET_ALL + "\n" + Fore.CYAN + "ShadowForge-Toolkit v2 forged and ready. Type python main.py scan --help when recon drops." + Style.RESET_ALL

if __name__ == "__main__" or __name__ == "main":
    print(banner)