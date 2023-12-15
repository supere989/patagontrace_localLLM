## AI PCAP analyzer in your terminal

PCAP analyzer integrated with OpenAI's ChatGPT into your shell.

[![Patagontrace](https://i.postimg.cc/vTX5s2GV/patagontrace-screen.png)](https://i.postimg.cc/vTX5s2GV/patagontrace-screen.png)

### Description

Patagontrace provides AI-driven PCAP file analysis in your console, powered by ChatGPT. It includes customizable default prompts for common network troubleshooting, allowing users to adapt them to their specific scenarios. Additionally, the interactive session enables users to input their own prompts for tailored analysis.

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

