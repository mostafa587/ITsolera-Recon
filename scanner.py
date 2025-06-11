```py
import string
import selenium
import os
import argparse
from termcolor import colored
import colorama
import re
import subprocess
colorama.init()

#clear links
#sed 's/[?].*//' katana_output.txt | sort | uniq > cleanLinks.txt


#parameters
#grep -oE "[?&]([a-zA-Z0-9_]+)=" katana_output.txt | sed 's/[?&]\(.*\)=/\1/' | sort | uniq > paramters.txt


def run_nmap(target, flags):
    command = ["nmap"] + flags.split() + [target]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        with open("nmap_output.txt", "w") as f:
            f.write(result.stdout)
        
        print("nmap Scan complete. Output saved to 'nmap_output.txt'.")
    
    except subprocess.CalledProcessError as e:
        print("Nmap failed:", e)
        print(e.stderr)


def detect_with_whatweb(url):
    try:
        result = subprocess.check_output(['whatweb', url], text=True)
        result = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', result)
        with open("nmap_output.txt", "a") as f:
            f.write("\nwhatweb output:-\n")
            f.write(result)
        print("whatweb scan completed.")
    except subprocess.CalledProcessError as e:
        print(f"whatweb error: {e}")

def katana():
    try:
            cmd = "/home/slom/Programs/tools/katana/bin/katana -list live_hosts.txt > katana_output.txt"
            subprocess.run(cmd, shell=True,executable='/bin/zsh')
    except Exception as e:
        print("katana exception:", e)

def parameters_collection():
    cmd = r"grep -oE '[?&]([a-zA-Z0-9_]+)=' katana_output.txt | sed 's/[?&]\(.*\)=/\1/' | sort | uniq > paramters.txt"
    subprocess.run(cmd, shell=True)
# Example

def clean_katana_output():
    cmd = "sed 's/[?].*//' katana_output.txt | sort | uniq > cleanLinks.txt"
    subprocess.run(cmd, shell=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Nmap from Python")
    parser.add_argument("-t","--target", help="Target IP or domain")
    parser.add_argument("-f", "--flags", default="-sS", help="Nmap flags (e.g., \"-sV -p 22,80\")")
    
    args = parser.parse_args()
    run_nmap(args.target, args.flags)
    detect_with_whatweb(args.target)
    katana()
    parameters_collection()
    clean_katana_output()
```