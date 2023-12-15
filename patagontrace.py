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

def run_tshark_cmd_and_process_result(cmd):
    result = run_tshark_cmd(cmd)
    if result is None:
        print("Error running tshark command or tshark not found.")
        return ""
    result_text = ' '.join(result)
    if len(result_text) > 5000:
        result_text = result_text[:5000]
        print("Trimming pcap text to 5000 characters for AI processing.")
    return result_text

def pcap_to_txt(input_file):
    cmd = f'tshark -r {input_file}'
    return run_tshark_cmd_and_process_result(cmd)

def filtered_pcap_to_txt(input_file, filter_choice, filter_value):
    if filter_choice in ["IP", "Frame", "Protocol"]:
        tshark_filter = {
            "IP": "ip.addr == {}",
            "Frame": "frame.number == {}",
            "Protocol": "{}"
        }.get(filter_choice).format(filter_value)
    else:  # Custom filter
        tshark_filter = "{} == {}".format(filter_choice, filter_value)

    cmd = f'tshark -r {input_file} -Y "{tshark_filter}"'
    return run_tshark_cmd_and_process_result(cmd)

def print_full_pcap(input_file):
    cmd = f'tshark -r {input_file}'
    full_pcap_text = run_tshark_cmd(cmd)
    if full_pcap_text is None:
        print("Error running tshark command or tshark not found.")
    else:
        for line in full_pcap_text:
            print(line)

def is_valid_tshark_filter(input_file, custom_filter):
    test_cmd = f'tshark -r {input_file} -Y "{custom_filter}"'
    process = subprocess.Popen(test_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, error = process.communicate()
    return not error
	
# Other Functions

def display_main_menu():
    term_width = shutil.get_terminal_size((80, 20)).columns
    num_columns = 4
    column_width = term_width // num_columns
    filter_options = ["Protocol", "IP", "Frame", "Other", "None"]

    formatted_options = []

    for i, option in enumerate(filter_options):
        formatted_option = f"{i + 1} - {option}"
        padded_option = formatted_option.center(column_width)
        formatted_options.append(padded_option)

    print_pcap_option = Fore.WHITE + "P - Print PCAP".center(column_width) + Style.RESET_ALL
    formatted_options.append(print_pcap_option)

    print(
        Fore.YELLOW
        + "Select a filter option:".center(term_width)
        + "\n"
    )
    print(Fore.YELLOW + "=" * term_width)
    for formatted_option in formatted_options:
        print(Fore.YELLOW + formatted_option, end="")
        if (formatted_options.index(formatted_option) + 1) % num_columns == 0 and formatted_option != formatted_options[-1]:
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
    special_options = [
        Fore.WHITE + "0 - Go back to main menu".center(column_width) + Style.RESET_ALL,
        Fore.WHITE + "P - Print Current PCAP".center(column_width) + Style.RESET_ALL
    ]
    formatted_prompts.extend(special_options)

    print(
        Fore.YELLOW
        + "Choose a prompt, ask a question, or 'q' to quit:".center(term_width)
        + "\n"
    )
    print(Fore.YELLOW + "=" * term_width)
    for i, formatted_prompt in enumerate(formatted_prompts):
        print(Fore.YELLOW + formatted_prompt, end="")
        if (i + 1) % num_columns == 0 and i != len(formatted_prompts) - 1:
            print()
    print(Fore.YELLOW + "\n" + "=" * term_width + Style.RESET_ALL)

def get_user_input(prompt):
    term_width = shutil.get_terminal_size((80, 20)).columns
    padding = (term_width - len(prompt)) // 2
    sys.stdout.write("\033[K")  # Clear the line
    sys.stdout.write("\r" + " " * padding + prompt)
    sys.stdout.flush()
    try:
        return input()
    except (EOFError, KeyboardInterrupt):
        return "q"
def print_centered_no_newline(text):
    term_width = shutil.get_terminal_size((80, 20)).columns
    padding_left = (term_width - len(text)) // 2
    print(" " * padding_left + text, end="")

def center_multiline_string(s):
	term_width = shutil.get_terminal_size((80, 20)).columns
	centered_lines = []

	for line in s.split("\n"):
		padding_left = (term_width - len(line)) // 2
		centered_line = " " * padding_left + line
		centered_lines.append(centered_line)

	return "\n".join(centered_lines)
	
# --- CLI Chat Function ---
def main():
    openai.api_key = ""

    def parse_args():
        parser = argparse.ArgumentParser(description="Patagontrace: Analyze your pcap with ChatGPT")
        parser.add_argument("--model", default="gpt-3.5-turbo", choices=["gpt-4", "gpt-3.5-turbo", "code-davinci-002", "text-davinci-003"], help="Choose the API model to use")
        parser.add_argument("--temperature", default=0.7, type=float, help="Control the randomness of the response")
        parser.add_argument("--pcap", help="Path to pcap file for analysis")
        return parser.parse_args()

    args = parse_args()

    if not args.pcap:
        print("No pcap file provided. Exiting.")
        sys.exit(0)
	
    pcap_text = pcap_to_txt(args.pcap)  # Get the full pcap text

    print(Fore.YELLOW + center_multiline_string(ascii_logo))
    print(Fore.CYAN + "AI-Generated Overview of the PCAP:" + Style.RESET_ALL)
    initial_analysis_prompt = f"Provide a short overview of the following pcap:\n\n{pcap_text}"
    initial_response = openai.ChatCompletion.create(model=args.model, messages=[{"role": "system", "content": initial_analysis_prompt}], temperature=args.temperature)
    initial_analysis_overview = initial_response.choices[0].message['content'].strip()
    print(Fore.CYAN + initial_analysis_overview + Style.RESET_ALL + "\n")

    while True:
        display_main_menu()
        filter_choice = get_user_input("Select an option: ")

        if filter_choice.lower() in ["quit", "q", "bye"]:
            print(Fore.WHITE + "\nPatagontrace: In case I don’t see ya, good afternoon, good evening, and good night!\n")
            break

        if filter_choice.upper() == "P":
            print_full_pcap(args.pcap)
            continue

        filter_type = ["Protocol", "IP", "Frame", "Other", "None", "Print Full PCAP"][int(filter_choice) - 1]
        filter_value = ""
        current_pcap_text = pcap_text  # Default to full pcap text

        if filter_type == "Other":
            valid_filter = False
            while not valid_filter:
                filter_name = get_user_input("Enter custom filter name (e.g., diameter.cmd.code): ")
                if filter_name.lower() in ["quit", "q", "bye"]:
                    print("Exiting filter selection.")
                    break  # Exit the filter input loop
                filter_value = get_user_input(f"Enter value for {filter_name}: ")
                if filter_value.lower() in ["quit", "q", "bye"]:
                    print("Exiting filter selection.")
                    break  # Exit the filter input loop

                tshark_filter = f"{filter_name} == {filter_value}"
                valid_filter = is_valid_tshark_filter(args.pcap, tshark_filter)
                if not valid_filter:
                    print(Fore.RED + "Invalid filter. Please try again." + Style.RESET_ALL)

            if filter_name.lower() in ["quit", "q", "bye"] or filter_value.lower() in ["quit", "q", "bye"]:
                continue  # Return to the main menu

            current_pcap_text = filtered_pcap_to_txt(args.pcap, filter_name, filter_value)
			
        elif filter_type != "None":
            filter_value = get_user_input(f"Enter {filter_type} value to filter: ")
            current_pcap_text = filtered_pcap_to_txt(args.pcap, filter_type, filter_value)

        while True:
            display_prompt_menu()
            prompt_choice = get_user_input("Choose a prompt or ask a question: ")

            if prompt_choice.lower() in ["quit", "q", "bye"]:
                break

            if prompt_choice == "0":
                break  # Go back to filter selection

            if prompt_choice.upper() == "P":
                # Print the current PCAP and continue in the loop
                print("\n--- PCAP Data ---")
                print(current_pcap_text)
                print("\n--- End of PCAP Data ---\n")
                continue

            combined_prompt = ""
            if prompt_choice.strip().isdigit():
                prompt_index = int(prompt_choice.strip()) - 1
                if 0 <= prompt_index < len(prompts):
                    chosen_prompt = prompts[prompt_index].split(':')[1].strip()
                    if filter_type != "None":
                        combined_prompt = f"{chosen_prompt} focusing on {filter_type} {filter_value}: {current_pcap_text}"
                    else:
                        combined_prompt = f"{chosen_prompt}: {current_pcap_text}"
                else:
                    if filter_type != "None":
                        combined_prompt = f"{prompt_choice} focusing on {filter_type} {filter_value}: {current_pcap_text}"
                    else:
                        combined_prompt = f"{prompt_choice}: {current_pcap_text}"
				
            messages = [{"role": "user", "content": combined_prompt}]
            response = openai.ChatCompletion.create(model=args.model, messages=messages, temperature=args.temperature)
            reply = response.choices[0].message['content']
            print(Fore.YELLOW + "\nPatagontrace: " + reply + "\n")

        if prompt_choice.lower() in ["quit", "q", "bye"]:
            print(Fore.WHITE + "\nPatagontrace: In case I don’t see ya, good afternoon, good evening, and good night!\n")
            break

if __name__ == "__main__":
    main()
