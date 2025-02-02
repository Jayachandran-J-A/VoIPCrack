import os
import pyshark
import numpy as np
import soundfile as sf
import subprocess
import sys
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8')

def extract_voip_audio(pcap_file, output_file):
    """
    Extract and decode VoIP audio from GSM RTP packets.
    """
    rtp_streams = defaultdict(list)
    
    capture = pyshark.FileCapture(
        pcap_file, 
        display_filter='rtp and udp',
        only_summaries=False
    )
    
    for packet in capture:
        try:
            rtp_layer = packet.rtp
            payload = bytes.fromhex(rtp_layer.payload.replace(':', ''))
            
            try:
                src_ip = packet.ip.src if hasattr(packet, 'ip') else packet.ipv6.src
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else packet.ipv6.dst
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
            except Exception:
                continue
            
            stream_key = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")
            rtp_streams[stream_key].append({
                'seq': int(rtp_layer.seq),
                'timestamp': int(rtp_layer.timestamp),
                'payload': payload
            })
        
        except Exception as e:
            print(f"Packet processing error: {e}")
    
    decoded_streams = []
    for stream_key, packets in rtp_streams.items():
        try:
            print(f"Processing stream: {stream_key}")
            sorted_packets = sorted(packets, key=lambda x: x['seq'])
            
            gsm_data = b''
            for packet in sorted_packets:
                gsm_data += packet['payload']
            
            process = subprocess.run([
                "ffmpeg", "-y", "-f", "gsm", "-i", "-", output_file
            ], input=gsm_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            
            audio, samplerate = sf.read(output_file, dtype='int16')
            decoded_streams.append(audio)
            
        except Exception as e:
            print(f"Stream processing error for {stream_key}: {e}")
    
    if decoded_streams:
        print(f"Found {len(decoded_streams)} valid streams")
        max_length = max(len(stream) for stream in decoded_streams)
        synchronized_streams = [
            np.pad(stream, (0, max_length - len(stream)), mode='constant')
            for stream in decoded_streams
        ]
        
        if len(synchronized_streams) > 1:
            mixed_audio = np.sum(synchronized_streams, axis=0) / len(synchronized_streams)
            final_audio = np.int16(mixed_audio)
        else:
            final_audio = synchronized_streams[0]
        
        sf.write(output_file, final_audio, 8000)
        print(f"Synchronized audio extracted to {output_file}")
    else:
        print("No viable audio streams found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_file = 'output.wav'
    extract_voip_audio(pcap_file, output_file)