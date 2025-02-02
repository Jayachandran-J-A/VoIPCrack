import os
import pyshark
import numpy as np
import soundfile as sf
import audioop
import sys
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8')

def extract_voip_audio(pcap_file, output_file):
    """
    Extract and decode VoIP audio from PCMU RTP packets.
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
            
            stream_samples = []
            buffer = b''
            
            for packet in sorted_packets:
                payload = packet['payload']
                buffer += payload
                
                while len(buffer) >= 160:
                    chunk = buffer[:160]
                    buffer = buffer[160:]
                    try:
                        decoded = audioop.ulaw2lin(chunk, 2)
                        stream_samples.extend(np.frombuffer(decoded, dtype=np.int16))
                    except Exception as e:
                        print(f"Decoding error: {e}")
            
            if stream_samples:
                print(f"Successfully decoded {len(stream_samples)} samples for stream {stream_key}")
                samples_array = np.array(stream_samples, dtype=np.float32)
                if np.max(np.abs(samples_array)) > 0:
                    samples_array = samples_array / np.max(np.abs(samples_array)) * 32767
                decoded_streams.append(samples_array.astype(np.int16))
        
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
