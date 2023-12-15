## AI PCAP analyzer in your terminal

PCAP analyzer integrated with OpenAI's ChatGPT into your shell.

![Patagontrace](https://i.postimg.cc/gkj7QV25/patagontrace.png) 


### Description

AI-powered PCAP analysis utility accessible directly from your console. It enables in-depth and comprehensive analysis and troubleshooting of PCAP files through ChatGPT integration. The prompts are customizable to suit typical use cases.

### Dependencies

* Install module dependencies using pip:
 ```pip install -r requirements.txt```

* OpenAI API key - you can get one [here](https://platform.openai.com/overview) - Dashboard - Settings - View API Keys - Generate


### Installing

* Clone the repo and copy the folder to a permanent location.

* Open patagontrace.py and update `openai.api_key = "API_KEY"` .

* Create an alias pointing at the script's location, either in your bash profile *~/.bash_profile* or *~/.bashrc* or *~/.zshrc* - i.e:
 ```alias patagontrace='python3 /path/to/patagontrace.py'```

### Usage

Using your chosen alias you can call it from shell and pass the pcap name to be analyzed.

```patagontrace --pcap ../sip-routing-error-wireshark.pcap```

```patagontrace --pcap ../dia-links.pcap```

To end the interactive chat, use either `bye`,`quit`,`q` or `ctrl+c`.

### Data Confidentiality
This tool utilizes OpenAI's ChatGPT for processing and analysis. Please be aware that any data provided may be used in accordance with OpenAI's use-case policy. We recommend not sharing any sensitive or personal information. For further details, please refer to OpenAI's privacy policy.


