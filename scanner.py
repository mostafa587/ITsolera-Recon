#!/usr/bin/env python3
import os
import argparse
from termcolor import colored
import colorama
import re
import subprocess
colorama.init()

#clear links
#sed 's/[?].*//' katana_output.txt | sort | uniq > cleanLinks.txt

ScriptDir = os.getcwd() # Get the current working directory
Results_path = os.path.join(ScriptDir, "ReconnResult")
#parameters
#grep -oE "[?&]([a-zA-Z0-9_]+)=" katana_output.txt | sed 's/[?&]\(.*\)=/\1/' | sort | uniq > paramters.txt
if not os.path.exists(Results_path):
    os.makedirs(Results_path)

def run_nmap(target, flags):
    command = ["nmap"] + flags.split() + [target]

    try:
        print(colored(f"Running nmap scan on {target} with flags: {flags}", "green"))
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        nmap_output_path = os.path.join(Results_path, "nmap_output.txt")
        with open(nmap_output_path, "w") as f:
            f.write(result.stdout)
        
        print(f"nmap Scan complete. Output saved to: {nmap_output_path}.")
    
    except subprocess.CalledProcessError as e:
        print("Nmap failed:", e)
        print(e.stderr)


def detect_with_whatweb(url):
    try:
        print(colored(f"Running whatweb scan on {url}", "green"))
        result = subprocess.check_output(['whatweb', url], text=True)
        result = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', result)

        nmap_output_path = os.path.join(Results_path, "nmap_output.txt")

        with open(nmap_output_path, "a") as f:
            f.write("\nwhatweb output:-\n")
            f.write(result)
        print("whatweb scan completed with in nmap_output.txt.")
    except subprocess.CalledProcessError as e:
        print(f"whatweb error: {e}")

def katana(alive_hosts_path):
    try:
            katana_path = "/home/mostafa/MAIN/TOOLS/GO/bin//katana"  # Edit this path to your katana binary location
            katana_output = os.path.join(Results_path, "katana_output.txt")
            cmd = f"{katana_path} -list {alive_hosts_path} > {katana_output}" 
            subprocess.run(cmd, shell=True,executable='/bin/zsh')
    except Exception as e:
        print("katana exception:", e)

def parameters_collection():
    print(colored("Collecting parameters from katana output...", "green"))
    katana_output = os.path.join(Results_path, "katana_output.txt")
    parameters_output = os.path.join(Results_path, "parameters.txt")
    cmd = f"grep -oE '[?&]([a-zA-Z0-9_]+)=' {katana_output} | sed 's/[?&]\\(.*\\)=/\\1/' | sort | uniq > {parameters_output}"
    subprocess.run(cmd, shell=True)
# Example

def clean_katana_output():
    print(colored("Cleaning katana output...", "green"))
    katana_output = os.path.join(Results_path, "katana_output.txt")
    clean_links = os.path.join(Results_path, "cleanLinks.txt")
    cmd = f"sed 's/[?].*//' {katana_output} | sort | uniq > {clean_links}"
    subprocess.run(cmd, shell=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Nmap from Python")
    parser.add_argument("-t","--target", help="Target IP or domain")
    parser.add_argument("-f", "--flags", default="-sS", help="Nmap flags (e.g., \"-sV -p 22,80\")")

    parser.add_argument("-oH", "--output_httpx", type=str, default=os.path.join(Results_path, "Alive_subs.txt"), help="Path for file or httpx results for alive hosts(default: Alive_subs.txt in current directory)")
    
    args = parser.parse_args()
    run_nmap(args.target, args.flags)
    detect_with_whatweb(args.target)
    katana(args.output_httpx)
    parameters_collection()
    clean_katana_output()
