# Required imports
import subprocess
import sys
import openai
import random
import string
import colorama
import shutil
import argparse
import readline
from colorama import Fore, Back, Style

# Assuming extras.py contains greeting and lamp
from src.extras import greeting, lamp
from src.prompts import prompts
ascii_logo="""
██████╗░░█████╗░████████╗░█████╗░░██████╗░░█████╗░███╗░░██╗████████╗██████╗░░█████╗░░█████╗░███████╗
██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔════╝░██╔══██╗████╗░██║╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝
██████╔╝███████║░░░██║░░░███████║██║░░██╗░██║░░██║██╔██╗██║░░░██║░░░██████╔╝███████║██║░░╚═╝█████╗░░
██╔═══╝░██╔══██║░░░██║░░░██╔══██║██║░░╚██╗██║░░██║██║╚████║░░░██║░░░██╔══██╗██╔══██║██║░░██╗██╔══╝░░
██║░░░░░██║░░██║░░░██║░░░██║░░██║╚██████╔╝╚█████╔╝██║░╚███║░░░██║░░░██║░░██║██║░░██║╚█████╔╝███████╗
╚═╝░░░░░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚═╝░╚═════╝░░╚════╝░╚═╝░░╚══╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚══════╝
"""
# --- PCAP Analyzer Functions ---
def run_tshark_cmd(cmd):
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    if error:
        print(f"Error: {error.decode('utf-8')}")
        return None
    return output.decode('utf-8').splitlines()

def pcap_to_txt(input_file, protocol):
    cmd = f'tshark -r {input_file} -Y "{protocol}"'
    result = run_tshark_cmd(cmd)
    if result is None:
        print("Error running tshark command or tshark not found.")
        return ""

    # Join the lines and trim to 5000 characters
    result_text = ' '.join(result)
    if len(result_text) > 5000:
        result_text = result_text[:5000]
        print("Trimming pcap text to 5000 characters for AI processing.")
    return result_text

# Diameter specific functions
def dia_list_imsis(input_file, protocol):
    cmd = f'tshark -r {input_file} -Y "{protocol}" -T fields -e e212.imsi'
    return list(set(run_tshark_cmd(cmd)))

def dia_list_session_ids(input_file, protocol, imsi):
    cmd = f'tshark -r {input_file} -Y "{protocol} && e212.imsi == {imsi}" -T fields -e frame.time -e diameter.Session-Id -e diameter.Auth-Application-Id'
    return run_tshark_cmd(cmd)

def dia_list_session_ids(input_file, protocol, imsi):
    cmd = f'tshark -r {input_file} -Y "{protocol} && e212.imsi == {imsi}" -T fields -e frame.time -e diameter.Session-Id -e diameter.Auth-Application-Id'
    return run_tshark_cmd(cmd)
# Other Functions
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
        parser = argparse.ArgumentParser(description="Patagontrace: Analyze your pcap with ChatGPT")
        parser.add_argument("--model", default="gpt-3.5-turbo", choices=["gpt-4", "gpt-3.5-turbo", "code-davinci-002", "text-davinci-003"], help="Choose the API model to use")
        parser.add_argument("--temperature", default=0.7, type=float, help="Control the randomness of the response")
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

    if args.pcap and args.protocol:
        pcap_text = pcap_to_txt(args.pcap, args.protocol)
        if pcap_text:
            # Updated analysis prompt
            analysis_prompt = (f"Analyze the pcap trace focusing on {args.protocol}. Output structured in three sections:\n"
                               f"1) Summary of Findings: Overview of pcap for the protocol.\n"
                               f"2) Identified Concerns: Issues in pcap.\n"
                               f"3) Troubleshooting Suggestions: Steps to resolve issues.\n\n"
                               f"{pcap_text}")
            response = openai.ChatCompletion.create(model=args.model, messages=[{"role": "system", "content": analysis_prompt}], temperature=args.temperature)
            analysis_overview = response.choices[0].message['content'].strip()

            print(Fore.YELLOW + center_multiline_string(ascii_logo))
            # Display analysis overview
            print(Fore.CYAN + analysis_overview + Style.RESET_ALL + "\n")
            
            # Display prompt menu
            display_prompt_menu()
        else:
            print("Failed to extract text from pcap file.")
            sys.exit(0)
    else:
        print("No pcap file provided. Exiting.")
        sys.exit(0)

    messages = []
    while True:
        print_centered_no_newline(Fore.BLUE + "You: ")
        user_input = get_user_input(Fore.BLUE + "")
        if user_input.lower() in ["quit", "q", "bye"]:
            print(Fore.YELLOW + "\nPatagontrace: Until you drag me out of the packets again...\n")
            break

        if user_input.strip().isdigit() and 1 <= int(user_input.strip()) <= len(prompts):
            prompt = prompts[int(user_input.strip()) - 1].split(':')[1].strip()
        else:
            prompt = user_input.strip()

        messages.append({"role": "user", "content": prompt + "\n\n" + pcap_text})
        response = openai.ChatCompletion.create(model=args.model, messages=messages, temperature=args.temperature)
        reply = response.choices[0].message['content']

        messages.append({"role": "assistant", "content": reply})
        print(Fore.YELLOW + "\nPatagontrace: " + reply + "\n")

if __name__ == "__main__":
    main()
