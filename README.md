**VoIPCrack: VoIP Call Interception and Analysis**
--------------------------------------------------

**VoIPCrack** is a comprehensive solution for intercepting and analyzing VoIP traffic. It allows users to capture and process VoIP call data, extract audio streams, transcribe conversations, and retrieve caller/callee details, including geographic information. Designed for forensic analysis and network security, the tool automates the entire VoIP call analysis process.

**Features**
------------

1.  **Dual-Mode Input**:
    

*   Process pre-recorded .pcapng files captured using tools like Wireshark or tshark.
    
*   Capture real-time VoIP traffic using SIP spoofing techniques.
    

1.  **VoIP Traffic Analysis**:
    

*   Capture and process SIP/SDP and RTP packets.
    
*   Decode RTP audio streams using standard codecs.
    

1.  **Audio Extraction**:
    

*   Reconstruct audio from RTP packets and save as .wav files.
    
*   Support for stereo audio channel separation.
    

1.  **Conversation Transcription**:
    

*   AI-powered speech-to-text transcription using OpenAI Whisper.
    
*   Generate synchronized transcripts with speaker labels.
    

1.  **Caller and Callee Information Extraction**:
    

*   Parse SIP headers to identify caller and callee IDs, IP addresses, and domains.
    
*   Retrieve geographic location (city, state, country) using APIs like ipinfo.io.
    

1.  **Report Generation**:
    

*   Generate comprehensive reports containing:
    
*   Caller and callee SIP addresses.
    
*   IP address, domain name, and transport protocol.
    
*   Geographic location.
    
*   Transcribed conversation.
    

**Technical Highlights**
------------------------

*   **Packet Capture**: Uses pyshark for live traffic capture and .pcapng file analysis.
    
*   **Audio Processing**: Leverages librosa and soundfile for audio extraction and channel separation.
    
*   **Speech Recognition**: Integrates OpenAI Whisper for high-accuracy transcription.
    
*   **Geolocation**: Employs APIs to fetch detailed geographic information for IP addresses.
    
*   **Command-line Tools**: Utilizes tshark for efficient SIP and RTP data parsing.
    

**Installation**
----------------

### **Prerequisites**

*   Python 3.8 or higher
    
*   Required libraries: pyshark, librosa, soundfile, whisper, requests, numpy
    

### **Installation Steps**

1.  Clone the repository:
    

Bash

git clone https://github.com/Jayachandran-J-A/VoIPCrack.gitcd VoIPCrack

1.  Install dependencies:
    

Bash

pip install -r requirements.txt

1.  Ensure tshark is installed:
    

Bash

sudo apt-get install tshark

1.  Configure ipinfo.io API (optional for geolocation).
    

**Usage**
---------

### **1\. Capturing and Processing VoIP Traffic**

To capture SIP and RTP packets during a live VoIP call:

Bash

python capture\_voip.py

**Modify the INTERFACE variable in the script to specify the network interface.**

### **2\. Extract Audio and Transcribe Conversation**

Process a stereo .wav file to extract and transcribe a conversation:

Bash

python transcribe\_audio.py Conversation.wav

### **3\. Analyze VoIP Traffic for Caller/Callee Details**

Analyze a .pcap file for SIP information:

Bash

python analyze\_voip.py path/to/capture.pcap

**Output**
----------

*   Transcribed Conversation: Saved as conversation\_transcript.txt.
    
*   Caller and Callee Information: Saved in call\_info.txt.
    
*   Processed Audio Files: Saved in the output/ directory.
    

**Methodology**
---------------

**Input Selection:** Users can upload a .pcap file or configure the system to capture live traffic.

**Packet and Audio Analysis:** Filter SIP and RTP packets, reconstruct audio, and save as .wav.

**Speech Processing:** Convert extracted audio to text with speaker labels.

**Report Generation:** Compile caller/callee information, geolocation, and transcriptions into detailed reports.

**Tools and Frameworks**
------------------------

*   Network Analysis: pyshark, tshark
    
*   Audio Processing: librosa, soundfile
    
*   Speech Recognition: whisper
    
*   Geolocation: ipinfo.io (optional)
    

**Future Enhancements**
-----------------------

*   Real-time transcription and multilingual support.
    
*   Log generation in multiple formats (CSV, HTML, PDF).
    
*   RTP packet crafting and injection for VoIP stream manipulation.
    

**Disclaimer**
--------------

This tool is intended for ethical research and educational purposes. Any misuse for malicious activities is strictly prohibited.
