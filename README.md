## AI PCAP analyzer in your terminal

PCAP analyzer integrated with OpenAI's ChatGPT into your shell.

![Patagontrace](https://i.postimg.cc/15LqNFjJ/patagontrace.png) 


### Description

An AI-powered PCAP analysis utility that you can access directly from your console. It facilitates in-depth and comprehensive analysis and troubleshooting of PCAP files through ChatGPT integration. By default, the tool provides prompts tailored to 3G, 4G, and 5G protocols.

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

Using your chosen alias you can call it from shell and pass the pcap name and the protocol to be analyzed.

patagontrace --pcap ../sip-routing-error-wireshark.pcap --protocol sip
patagontrace --pcap ../dia-links.pcap --protocol diameter

The default model used is `gpt-3.5-turbo` for a more fluent experience as its replies are much faster and API pricing is significantly cheaper.

You can switch API model using the `--model` argument (run without `--model` to use the default model) if you'd like to to use gpt-4:

```$ patagontrace --model gpt-4```

`--model` will also accept *code-davinci-002* & *text-davinci-003* - other API models can be seen here [OpenAI ChatGPT API Models](https://platform.openai.com/docs/models) and added as required to the script.

The temperature used is `0.7` - which appears to be a good balance between creativity and focused responses. 

You can switch temperature using the `--temp` argument (run without `--temp` to use the default value).

To end the interactive chat, use either `bye`,`quit`,`q` or `ctrl+c`.

### Data Confidentiality and Privacy
This tool utilizes OpenAI's ChatGPT to analyze network traffic data extracted from pcap files. It's important to understand that when using this tool, the data you provide (such as IP addresses, IMSIs, MSISDNs, and other network details) is sent to ChatGPT for analysis.

### Data Handling
Confidentiality: Please be aware that the data you input into the tool is processed by ChatGPT, which is a publicly available language model developed by OpenAI.
Data Usage: The data sent to ChatGPT may be used by OpenAI to improve the performance and capabilities of their models. It's important to consider the sensitivity of the data you are analyzing with this tool.

### User Responsibility
It is the user's responsibility to ensure that the use of this tool and ChatGPT complies with applicable data protection laws and organizational policies.
Users should be aware of the data they are sharing and should anonymize any sensitive or personally identifiable information before analysis.

### Disclaimer
The developers of this tool are not responsible for any data breaches or leaks that may occur due to the use of ChatGPT. Users should use this tool at their own risk and ensure they are comfortable with the data being shared with an external service.
