import subprocess
import sys
import openai
import argparse
import colorama
from colorama import Fore, Style

# --- PCAP Analyzer Functions ---
def run_tshark_cmd(cmd):
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    if error:
        print(f"Error: {error.decode('utf-8')}")
        return None
    return output.decode('utf-8').splitlines()

def list_imsis(input_file, protocol):
    cmd = f'tshark -r {input_file} -Y "{protocol}" -T fields -e e212.imsi'
    return list(set(run_tshark_cmd(cmd)))

def list_session_ids(input_file, protocol, imsi):
    cmd = f'tshark -r {input_file} -Y "{protocol} && e212.imsi == {imsi}" -T fields -e frame.time -e diameter.Session-Id -e diameter.Auth-Application-Id'
    return run_tshark_cmd(cmd)

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

def pcap_to_txt(input_file, protocol, imsi, session_id):
    cmd = f'tshark -r {input_file} -Y "diameter && e212.imsi == {imsi} && diameter.Session-Id == \\"{session_id}\\"" -T fields -e frame.time -e ip.src -e ip.dst -e diameter.Session-Id -e diameter.cmd.code -e diameter.applicationId -e diameter.Result-Code -e diameter.CC-Request-Type -e diameter.CC-Request-Number -e diameter.Origin-Host -e diameter.Origin-Realm -e diameter.Destination-Host -e diameter.Destination-Realm'
    result = run_tshark_cmd(cmd)
    return ' '.join(result) if result else None

# --- CLI Chat Function ---
def main():
    parser = argparse.ArgumentParser(description="Genie: Chat with ChatGPT")
    parser.add_argument("--model", default="gpt-3.5-turbo", choices=["gpt-4", "gpt-3.5-turbo", "code-davinci-002", "text-davinci-003"], help="Choose the API model to use")
    parser.add_argument("--temperature", default=0.7, type=float, help="Control the randomness of the response")
    parser.add_argument("--pcap", help="Path to pcap file for analysis")
    parser.add_argument("--protocol", help="Protocol used in pcap file")
    args = parser.parse_args()

    openai.api_key = "YOUR_API_KEY"
    messages = []

    if args.pcap and args.protocol:
        # PCAP Analysis Mode
        initial_prompt = "Provide an overview of this pcap file: " + args.pcap + " with protocol " + args.protocol
        messages.append({"role": "user", "content": initial_prompt})

        response = openai.ChatCompletion.create(model=args.model, messages=messages, temperature=args.temperature)
        overview_reply = response["choices"][0]["message"]["content"]
        messages.append({"role": "assistant", "content": overview_reply})
        print(Fore.YELLOW + "\nGenie: " + overview_reply + "\n")
    else:
        # Regular Chat Mode
        print(Fore.BLUE + "Enter your question or 'q' to quit: ", end="")
        user_input = input()
        if user_input.lower() in ['q', 'quit']:
            print(Fore.YELLOW + "Exiting Genie chat.")
            sys.exit(0)
        messages.append({"role": "user", "content": user_input})

    while True:
        response = openai.ChatCompletion.create(model=args.model, messages=messages, temperature=args.temperature)
        reply = response["choices"][0]["message"]["content"]

        messages.append({"role": "assistant", "content": reply})
        print(Fore.YELLOW + "\nGenie: " + reply + "\n")

        print(Fore.BLUE + "Your turn: ", end="")
        user_input = input()
        if user_input.lower() in ['q', 'quit']:
            print(Fore.YELLOW + "Exiting Genie chat.")
            break
        messages.append({"role": "user", "content": user_input})

if __name__ == "__main__":
    main()
