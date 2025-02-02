import pyshark
import argparse
import subprocess

def extract_codec(pcap_file):
    codecs = set()
    cap = pyshark.FileCapture(pcap_file, display_filter='sip and sdp')

    for packet in cap:
        if hasattr(packet, 'sip'):
            codec = packet.sip._all_fields.get('sdp.mime.type', None)
            if codec:
                codecs.add(codec)
    
    return codecs

def call_decoder(codec, pcap_file):
    codec_mapping = {
        'opus': 'opus_audio.py',
        'gsm': 'gsm_audio.py',
        'g729': 'g729_audio.py',
        'pcma': 'pcma_audio.py',
        'pcmu': 'pcmu_audio.py'
    }
    
    script = codec_mapping.get(codec.lower())
    if script:
        print(f"Calling {script} for codec {codec}")
        subprocess.run(['python', script, pcap_file])
    else:
        print(f"No decoder found for codec: {codec}")

def main():
    parser = argparse.ArgumentParser(description='Extract codec details from a PCAP file and call appropriate decoder.')
    parser.add_argument('pcap_file', help='Path to the PCAP file')
    args = parser.parse_args()
    
    codecs = extract_codec(args.pcap_file)
    
    if codecs:
        print("Extracted Codecs:")
        for codec in codecs:
            print(f"Codec: {codec}")
            call_decoder(codec, args.pcap_file)
    else:
        print("No codec information found.")

if __name__ == '__main__':
    main()
