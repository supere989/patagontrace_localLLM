import openai
import sys
import random
import string
import colorama
import shutil
import argparse
import readline
from src.extras import greeting, lamp
from src.prompts import prompts
from colorama import Fore, Back, Style

# --- PCAP Analyzer Functions ---
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

def dia_list_session_ids(input_file, protocol, imsi):
    cmd = f'tshark -r {input_file} -Y "{protocol} && e212.imsi == {imsi}" -T fields -e frame.time -e diameter.Session-Id -e diameter.Auth-Application-Id'
    return run_tshark_cmd(cmd)

def dia_pcap_to_txt(input_file, protocol):
    cmd = f'tshark -r {input_file} -Y {protocol} -T fields -e frame.time -e ip.src -e ip.dst -e diameter.Session-Id -e diameter.cmd.code -e diameter.applicationId -e diameter.Result-Code -e diameter.CC-Request-Type -e diameter.CC-Request-Number -e diameter.Origin-Host -e diameter.Origin-Realm -e diameter.Destination-Host -e diameter.Destination-Realm'
    result = run_tshark_cmd(cmd)
    return ' '.join(result) if result else None

def dia_filtered_pcap_to_txt(input_file, protocol, imsi, session_id):
    cmd = f'tshark -r {input_file} -Y "{protocol} && e212.imsi == {imsi} && diameter.Session-Id == \\"{session_id}\\"" -T fields -e frame.time -e ip.src -e ip.dst -e diameter.Session-Id -e diameter.cmd.code -e diameter.applicationId -e diameter.Result-Code -e diameter.CC-Request-Type -e diameter.CC-Request-Number -e diameter.Origin-Host -e diameter.Origin-Realm -e diameter.Destination-Host -e diameter.Destination-Realm'
    result = run_tshark_cmd(cmd)
    return ' '.join(result) if result else None

def sig_pcap_to_txt(input_file):
    cmd = f'tshark -r {input_file} -Y {protocol} -T fields -e frame.time -e ip.src -e ip.dst -e diameter.Session-Id -e diameter.cmd.code -e diameter.applicationId -e diameter.Result-Code -e diameter.CC-Request-Type -e diameter.CC-Request-Number -e diameter.Origin-Host -e diameter.Origin-Realm -e diameter.Destination-Host -e diameter.Destination-Realm'
    result = run_tshark_cmd(cmd)
    return ' '.join(result) if result else None
    
def sip_pcap_to_txt(input_file, protocol):
    cmd = f'tshark -r {input_file} -Y {protocol} -T fields -e frame.time -e ip.src -e ip.dst -e diameter.Session-Id -e diameter.cmd.code -e diameter.applicationId -e diameter.Result-Code -e diameter.CC-Request-Type -e diameter.CC-Request-Number -e diameter.Origin-Host -e diameter.Origin-Realm -e diameter.Destination-Host -e diameter.Destination-Realm'
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


# --- CLI Chat Function ---
def main():
    openai.api_key = "YOUR_API_KEY"

    def parse_args():
        parser = argparse.ArgumentParser(description="Genie: Chat with ChatGPT")
        parser.add_argument("--model", default="gpt-3.5-turbo", choices=["gpt-4", "gpt-3.5-turbo", "code-davinci-002", "text-davinci-003"], help="Choose the API model to use")
        parser.add_argument("--temperature", default=0.7, type=float, help="Control the randomness of the response")
        parser.add_argument("question", nargs="*", help="Optional question for non-interactive mode")
        parser.add_argument("--pcap", help="Path to pcap file for analysis")
        parser.add_argument("--protocol", help="Protocol used in pcap file")
        return parser.parse_args()

    def display_prompt_menu():
        term_width = shutil.get_terminal_size((80, 20)).columns
        num_columns = 3
        column_width = term_width // num_columns
        formatted_prompts = []

        for i, prompt in enumerate(prompts):
            formatted_prompt = f"{i + 1} - {prompt.split(':')[0]}"
            padded_prompt = formatted_prompt.center(column_width)
            formatted_prompts.append(padded_prompt)

        print(
            Fore.YELLOW
            + "Ask a question, choose a prompt, or 'q' to quit:".center(term_width)
            + "\n"
        )
        print(Fore.YELLOW + "=" * term_width)
        for i, formatted_prompt in enumerate(formatted_prompts):
            print(Fore.YELLOW + formatted_prompt, end="")
            if (i + 1) % num_columns == 0 and i != len(formatted_prompts) - 1:
                print()
        print(Fore.YELLOW + "\n" + "=" * term_width + Style.RESET_ALL)

    def center_multiline_string(s):
        term_width = shutil.get_terminal_size((80, 20)).columns
        centered_lines = []

        for line in s.split("\n"):
            padding_left = (term_width - len(line)) // 2
            centered_line = " " * padding_left + line
            centered_lines.append(centered_line)

        return "\n".join(centered_lines)

    def get_user_input(prompt):
        try:
            return input(prompt)
        except (EOFError, KeyboardInterrupt):
            return "q"

    def print_centered_no_newline(text):
        term_width = shutil.get_terminal_size((80, 20)).columns
        padding_left = (term_width - len(text)) // 2
        print(" " * padding_left + text, end="")
        
    args = parse_args()
    pcap_overview = None

    if args.pcap and args.protocol:
        # Process the pcap file for Diameter and extract text
        if args.protocol = diameter
        pcap_text = dia_pcap_to_txt(args.pcap, args.protocol)
        if args.protocol = sigtran
        pcap_text = sig_pcap_to_txt(args.pcap, args.protocol)
        if args.protocol = sip
        pcap_text = sip_pcap_to_txt(args.pcap, args.protocol)
        if pcap_text:
            print(f"Extracted text from pcap: {pcap_text[:500]}...")  # Display a snippet for debug

            # Now pass this text to ChatGPT for analysis
            analysis_prompt = f"Provide a short overview (network elements and their IPs, call flow, potential issues) of the following pcap traffic with focus on protocol {args.protocol}: \n\n{pcap_text}"
            print(f"Sending analysis prompt to ChatGPT: {analysis_prompt[:500]}...")  # Debug print
            response = openai.ChatCompletion.create(model=args.model, messages=[{"role": "system", "content": analysis_prompt}], temperature=args.temperature)
            analysis_overview = response.choices[0].message['content'].strip()

            print(Fore.CYAN + analysis_overview + Style.RESET_ALL + "\n")
        else:
            print("Failed to extract text from pcap file.")

        display_prompt_menu()


    if args.question:
        prompt = " ".join(args.question).rstrip(string.punctuation)
    else:
        print(Fore.YELLOW + center_multiline_string(lamp))
        if pcap_overview:
            print(Fore.YELLOW + center_multiline_string(pcap_overview) + "\n")
        if pcap_overview:
            print(Fore.CYAN + pcap_overview + Style.RESET_ALL + "\n")
        display_prompt_menu()
        print_centered_no_newline(Fore.BLUE + "You: ")
        user_input = get_user_input(Fore.BLUE + "")
        prompt = user_input.strip() if user_input.strip() else prompts[0]

    messages = []
    while True:
        if prompt.lower() in ["quit", "q", "bye"]:
            print(Fore.YELLOW + "\nGenie: Farewell, master. Until you drag me out of bed again...\n")
            break

        messages.append({"role": "user", "content": prompt})
        response = openai.ChatCompletion.create(model=args.model, messages=messages, temperature=args.temperature)
        reply = response.choices[0].message.content

        messages.append({"role": "assistant", "content": reply})
        print(Fore.YELLOW + "\nGenie: " + reply + "\n")

        print_centered_no_newline(Fore.BLUE + "You: ")
        prompt = get_user_input(Fore.BLUE + "")

if __name__ == "__main__":
    main()
