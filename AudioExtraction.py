import os
import pyshark
import numpy as np
import soundfile as sf
import opuslib

def extract_voip_audio(pcap_file, output_file):
    """
    Advanced VoIP audio extraction with comprehensive packet handling
    """
    # Streams to track RTP packets
    rtp_streams = {}
    
    # Read PCAP file
    capture = pyshark.FileCapture(
        pcap_file, 
        display_filter='rtp and udp',
        only_summaries=False
    )
    
    # Packet collection with enhanced tracking
    for packet in capture:
        try:
            rtp_layer = packet.rtp
            payload = bytes.fromhex(rtp_layer.payload.replace(':', ''))
            
            # Flexible IP source extraction
            try:
                src_ip = packet.ip.src if hasattr(packet, 'ip') else packet.ipv6.src
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else packet.ipv6.dst
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
            except Exception:
                continue
            
            stream_key = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")
            
            if stream_key not in rtp_streams:
                rtp_streams[stream_key] = []
            rtp_streams[stream_key].append((
                int(rtp_layer.seq), 
                int(rtp_layer.timestamp), 
                payload
            ))
        
        except Exception as e:
            print(f"Packet processing error: {e}")
    
    # Decoder configurations with extended parameters
    decoder_configs = [
        (48000, 1, [960, 480, 240, 120]),  # Expanded frame sizes
        (16000, 1, [480, 240, 120, 60]),
        (8000, 1, [240, 120, 60, 30])
    ]
    
    # Decode streams with improved completeness
    decoded_streams = []
    for stream_key, stream_packets in rtp_streams.items():
        # Advanced sorting considering timestamp
        sorted_packets = sorted(stream_packets, key=lambda x: (x[1], x[0]))
        
        for sample_rate, channels, frame_sizes in decoder_configs:
            try:
                decoder = opuslib.Decoder(sample_rate, channels)
                stream_samples = []
                
                for _, _, payload in sorted_packets:
                    for frame_size in frame_sizes:
                        try:
                            # More aggressive decoding strategy
                            decoded_payload = decoder.decode(
                                payload, 
                                frame_size, 
                                decode_fec=True
                            )
                            stream_samples.extend(
                                np.frombuffer(decoded_payload, dtype=np.int16)
                            )
                            break
                        except Exception:
                            continue
                
                if stream_samples:
                    decoded_streams.append(np.array(stream_samples))
                    break
            
            except Exception as e:
                print(f"Decoding error for {stream_key}: {e}")
    
    # Synchronize and merge streams
    if decoded_streams:
        max_length = max(len(stream) for stream in decoded_streams)
        
        synchronized_streams = [
            np.pad(stream, (0, max_length - len(stream)), mode='constant') 
            for stream in decoded_streams
        ]
        
        # Advanced channel interleaving
        merged_audio = np.column_stack(synchronized_streams[:2])
        
        # Write synchronized audio
        sf.write(output_file, merged_audio, 48000)
        print(f"Synchronized audio extracted to {output_file}")
    else:
        print("No viable audio streams found.")

# Usage example
pcap_file = input("Enter the path to the PCAP file: ")
output_file = input("Enter the name for the output WAV file: ")
extract_voip_audio(pcap_file, output_file)
