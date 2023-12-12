import subprocess
import sys
import openai
import argparse
import readline
import random
from colorama import Fore, Style

# --- PCAP Functions ---
def run_tshark_cmd(cmd):
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    if error:
        print(f"Error: {error.decode('utf-8')}")
        return None
    return output.decode('utf-8').splitlines()

def dia_list_imsis(input_file, protocol):
    cmd = f'tshark -r {input_file} -Y "{protocol}" -T fields -e e212.imsi'
    return list(set(run_tshark_cmd(cmd)))

def dia_list_session_ids(input_file, protocol, imsi):
    cmd = f'tshark -r {input_file} -Y "{protocol} && e212.imsi == {imsi}" -T fields -e frame.time -e diameter.Session-Id -e diameter.Auth-Application-Id'
    return run_tshark_cmd(cmd)
  
def dia_pcap_to_txt(input_file, protocol, imsi, session_id):
    cmd = f'tshark -r {input_file} -Y "diameter && e212.imsi == {imsi} && diameter.Session-Id == \\"{session_id}\\"" -T fields -e frame.time -e ip.src -e ip.dst -e diameter.Session-Id -e diameter.cmd.code -e diameter.applicationId -e diameter.Result-Code -e diameter.CC-Request-Type -e diameter.CC-Request-Number -e diameter.Origin-Host -e diameter.Origin-Realm -e diameter.Destination-Host -e diameter.Destination-Realm'
    result = run_tshark_cmd(cmd)
    return ' '.join(result) if result else None

def select_from_list(items, item_type):
    for i, item in enumerate(items, 1):
        print(f"{i}. {item}")
    while True:
        try:
            choice = int(input(f"Select a {item_type}: ")) - 1
            if 0 <= choice < len(items):
                return items[choice]
            else:
                print("Invalid selection. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")
