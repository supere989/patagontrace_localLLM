patagontrace-main]$ cat patagontrace.py
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

def get_field_names(protocol):
    field_names = {
        "sip": "Frame Number, Frame Time, Source IP, Destination IP, SIP Method, SIP Call-ID, SIP From, SIP To, SIP CSeq, SIP Via, SIP Contact, SIP User-Agent, UDP Source Port, UDP Destination Port",
        "diameter": "Frame Number, Frame Time, Source IP, Destination IP, Diameter Session-ID, Diameter Origin-Host, Diameter Origin-Realm, Diameter Destination-Host, Diameter Destination-Realm, Diameter Command Code, Diameter Result Code, Diameter Application ID, Diameter Flags Request",
        "sigtran": "Frame Number, Frame Time, Source IP, Destination IP, SCTP Source Port, SCTP Destination Port, SCTP Verification Tag, M3UA Message Class, M3UA Message Type, M3UA Affected Point Code",
        "gtp": "Frame Number, Frame Time, Source IP, Destination IP, GTP Message Type, GTP TEID",
        # Add other protocols if needed
    }
    return field_names.get(protocol, "Unknown protocol fields")
    
def pcap_to_txt(input_file, protocol):
    field_commands = {
        "sip": (
            '-T fields '
            '-e frame.number '
            '-e frame.time '
            '-e ip.src '
            '-e ip.dst '
            '-e sip.Method '
            '-e sip.Call-ID '
            '-e sip.From '
            '-e sip.To '
            '-e sip.CSeq '
            '-e sip.Via '
            '-e sip.Contact '
            '-e sip.User-Agent '
            '-e udp.srcport '
            '-e udp.dstport '
        ),
        "diameter": (
            '-T fields '
            '-e frame.number '
            '-e frame.time '
            '-e ip.src '
            '-e ip.dst '
            '-e diameter.Session-Id '
            '-e diameter.Origin-Host '
            '-e diameter.Origin-Realm '
            '-e diameter.Destination-Host '
            '-e diameter.Destination-Realm '
            '-e diameter.cmd.code '
            '-e diameter.Result-Code '
            '-e diameter.applicationId  '
            '-e diameter.flags.request '
        ),
        "sigtran": (
            '-T fields '
            '-e frame.number '
            '-e frame.time '
            '-e ip.src '
            '-e ip.dst '
            '-e sctp.srcport '
            '-e sctp.dstport '
            '-e sctp.verification_tag '
            '-e m3ua.message-class '
            '-e m3ua.message-type '
            '-e m3ua.affected-point-code '
        ),
        "gtp": (
            '-T fields '
            '-e frame.number '
            '-e frame.time '
            '-e ip.src '
            '-e ip.dst '
            '-e gtp.message_type '
            '-e gtp.teid '
        ),
        # Add other protocols if needed
    }

    if protocol in field_commands:
        cmd = f'tshark -r {input_file} -Y "{protocol}" {field_commands[protocol]}'
        print(f"Running command: {cmd}")  # For debugging
    else:
        print("Unsupported protocol.")
        return ""

    result = run_tshark_cmd(cmd)
    if result is None:
        print("Error running tshark command or tshark not found.")
        return ""

    # Join the lines and trim to 5000 characters
    result_text = ' '.join(result)
    if len(result_text) > 5000:
        result_text = result_text[:5000]
    return result_text



# Function to filter pcap based on user choice
def filtered_pcap_to_txt(input_file, protocol, filter_type, filter_value):
    cmd = ""
    if protocol == "sip":
        if filter_type == "IP":
            cmd = f'tshark -r {input_file} -Y "sip && ip.addr == {filter_value}"'
        # Add other SIP-specific filters if needed

    elif protocol == "diameter":
        if filter_type == "IP":
            cmd = f'tshark -r {input_file} -Y "diameter && ip.addr == {filter_value}"'
        elif filter_type == "IMSI":
            cmd = f'tshark -r {input_file} -Y "diameter && e212.imsi == {filter_value}"'
        # Add other Diameter-specific filters if needed

    elif protocol == "sigtran":
        if filter_type == "IP":
            cmd = f'tshark -r {input_file} -Y "m3ua && ip.addr == {filter_value}"'
        elif filter_type == "IMSI":
            cmd = f'tshark -r {input_file} -Y "m3ua && mobile-imsi == {filter_value}"'
        # Adjust Sigtran filters as per the protocol specifics

    elif protocol == "gtp":
        if filter_type == "IP":
            cmd = f'tshark -r {input_file} -Y "gtp && ip.addr == {filter_value}"'
        elif filter_type == "IMSI":
            cmd = f'tshark -r {input_file} -Y "gtp.imsi == {filter_value}"'
        # Add other GTP-specific filters if needed

    if cmd:
        result = run_tshark_cmd(cmd)
        if result:
            result_text = ' '.join(result)
            if len(result_text) > 5000:
                result_text = result_text[:5000] + "..."
                print("Trimming pcap text to 5000 characters for AI processing.")
            return result_text
        else:
            return ""
    else:
        return pcap_to_txt(input_file, protocol)




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

def display_main_menu():
    term_width = shutil.get_terminal_size((80, 20)).columns
    num_columns = 4
    column_width = term_width // num_columns
    filter_options = ["IP", "IMSI", "MSISDN", "None"]
    formatted_options = []

    for i, option in enumerate(filter_options):
        formatted_option = f"{i + 1} - {option}"
        padded_option = formatted_option.center(column_width)
        formatted_options.append(padded_option)

    print(
        Fore.YELLOW
        + "Select a filter option:".center(term_width)
        + "\n"
    )
    print(Fore.YELLOW + "=" * term_width)
    for i, formatted_option in enumerate(formatted_options):
        print(Fore.YELLOW + formatted_option, end="")
        if (i + 1) % num_columns == 0 and i != len(formatted_options) - 1:
            print()
    print(Fore.YELLOW + "\n" + "=" * term_width + Style.RESET_ALL)


def display_prompt_menu():
    term_width = shutil.get_terminal_size((80, 20)).columns
    num_columns = 3
    column_width = term_width // num_columns
    formatted_prompts = []

    for i, prompt in enumerate(prompts):
        formatted_prompt = f"{i + 1} - {prompt.split(':')[0]}"
        padded_prompt = formatted_prompt.center(column_width)
        formatted_prompts.append(padded_prompt)
    formatted_prompts.insert(0, "0 - Go back to main menu".center(column_width))

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


# --- CLI Chat Function ---
def main():
    openai.api_key = "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"

    def parse_args():
        parser = argparse.ArgumentParser(description="Patagontrace: Analyze your pcap with ChatGPT")
        parser.add_argument("--model", default="gpt-3.5-turbo", choices=["gpt-4", "gpt-3.5-turbo", "code-davinci-002", "text-davinci-003"], help="Choose the API model to use")
        parser.add_argument("--temperature", default=0.7, type=float, help="Control the randomness of the response")
        parser.add_argument("--pcap", help="Path to pcap file for analysis")
        parser.add_argument("--protocol", help="Protocol used in pcap file")
        return parser.parse_args()


    args = parse_args()

    if not args.pcap or not args.protocol:
        print("No pcap file or protocol provided. Exiting.")
        sys.exit(0)

    # Display ASCII art
    print(Fore.YELLOW + center_multiline_string(ascii_logo) + Style.RESET_ALL)

    # Initial analysis of pcap without filtering
    pcap_text = pcap_to_txt(args.pcap, args.protocol)
    field_description = get_field_names(args.protocol)

    # Analyze pcap with ChatGPT
    initial_analysis_prompt = (f"Analyze the pcap trace focusing on {args.protocol}.  The following fields are included: {field_description}. Output structured in three sections:\n"
                       f"1) Summary of Findings: Overview of pcap for the protocol.\n"
                       f"2) Identified Concerns: Issues in pcap.\n"
                       f"3) Troubleshooting Suggestions: Steps to resolve issues.\n\n"
                       f"{pcap_text}")
    #print(initial_analysis_prompt)
    initial_response = openai.ChatCompletion.create(model=args.model, messages=[{"role": "system", "content": initial_analysis_prompt}], temperature=args.temperature)
    initial_analysis_overview = initial_response.choices[0].message['content'].strip()
    print(Fore.CYAN + initial_analysis_overview + Style.RESET_ALL + "\n")

    filter_choice, filter_value = None, None
    while True:
        display_main_menu()
        print_centered_no_newline(Fore.WHITE + "Select an option: ")
        filter_choice = get_user_input(Fore.WHITE + "")

        if filter_choice == "1":
            print_centered_no_newline(Fore.WHITE + "Enter IP address to filter: ")
            filter_value = get_user_input(Fore.WHITE + "")
            filtered_pcap_text = filtered_pcap_to_txt(args.pcap, args.protocol, "IP", filter_value)
        elif filter_choice == "2":
            print_centered_no_newline(Fore.WHITE + "Enter IMSI to filter: ")
            filter_value = get_user_input(Fore.WHITE + "")
            filtered_pcap_text = filtered_pcap_to_txt(args.pcap, args.protocol, "IMSI", filter_value)
        elif filter_choice == "3":
            print_centered_no_newline(Fore.WHITE + "Enter MSISDN to filter: ")
            filter_value = get_user_input(Fore.WHITE + "")
            filtered_pcap_text = filtered_pcap_to_txt(args.pcap, args.protocol, "MSISDN", filter_value)
        elif filter_choice == "4":
            filtered_pcap_text = pcap_text
        elif filter_choice.lower() in ["quit", "q", "bye"]:
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)
            continue

        while True:
            display_prompt_menu()
            print_centered_no_newline(Fore.WHITE  + "Select an option or write your prompt: ")
            prompt_choice = get_user_input(Fore.WHITE  + "")

            if prompt_choice.lower() in ["quit", "q", "bye"]:
                break

            if prompt_choice == "0":
                # Go back to filter selection
                break

            combined_prompt = ""
            if prompt_choice.strip().isdigit():
                prompt_index = int(prompt_choice.strip()) - 1
                if 0 <= prompt_index < len(prompts):
                    chosen_prompt = prompts[prompt_index].split(':')[1].strip()
                    combined_prompt = f"{chosen_prompt} Protocol: {args.protocol} {filtered_pcap_text}"
            else:
                combined_prompt = f"{chosen_prompt} Protocol: {args.protocol} {filtered_pcap_text}"

            #print(combined_prompt)
            messages = [{"role": "user", "content": combined_prompt}]
            response = openai.ChatCompletion.create(model=args.model, messages=messages, temperature=args.temperature)
            reply = response.choices[0].message['content']

            print(Fore.YELLOW + "\nPatagontrace: " + reply + "\n")

        # If user chose to go back to the main menu
        if prompt_choice == "0":
            continue

        # If user wants to quit
        if prompt_choice.lower() in ["quit", "q", "bye"]:
            print(Fore.WHITE + "\nPatagontrace: In case I don’t see ya, good afternoon, good evening, and good night!\n")
            break

if __name__ == "__main__":
    main()
