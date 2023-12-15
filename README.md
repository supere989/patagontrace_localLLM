## AI PCAP analyzer in your terminal

PCAP analyzer integrated with OpenAI's ChatGPT into your shell.

![Patagontrace](https://i.postimg.cc/gkj7QV25/patagontrace.png) 


### Description

Patagontrace is an AI-powered PCAP analysis utility accessible directly from your console. It facilitates in-depth and comprehensive analysis of PCAP files, utilizing the advanced capabilities of ChatGPT. The tool is designed with customizable prompts to address typical networking and troubleshooting use cases.

### Dependencies

* Install module dependencies using pip:
 ```pip install -r requirements.txt```

* OpenAI API key - you can get one [here](https://platform.openai.com/overview) - Dashboard - Settings - View API Keys - Generate


### Installing

* Clone the Repository: Clone the repository using git clone, then navigate to the cloned folder.

* Open patagontrace.py and update the openai.api_key line with your API key.
`openai.api_key = "API_KEY"`

* Create an Alias: Set up an alias in your shell profile: *~/.bash_profile* or *~/.bashrc* or *~/.zshrc* - i.e:
 ```alias patagontrace='python3 /path/to/patagontrace.py'```

### Usage

To analyze a PCAP file, use the following command, replacing /path/to/file.pcap with the path to your PCAP file:

```patagontrace --pcap ../sip-routing-error-wireshark.pcap```

```patagontrace --pcap ../dia-links.pcap```

To end the interactive chat session, use the commands bye, quit, q, or the keyboard shortcut Ctrl+C.

For sample PCAP files, visit https://wiki.wireshark.org/SampleCaptures

### Data Confidentiality
This tool utilizes OpenAI's ChatGPT for processing and analysis. Please be cautious and avoid sharing any sensitive or personal information. For detailed information, refer to OpenAI's privacy policy.

