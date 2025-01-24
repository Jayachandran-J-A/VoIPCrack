import pyshark
import numpy as np
import soundfile as sf
import opuslib

def extract_voip_audio(pcap_file, output_file):
    """
    Extract audio from OPUS RTP packets with advanced error handling
    """
    # Streams to track RTP packets
    rtp_streams = {}
    
    # Read PCAP file
    capture = pyshark.FileCapture(pcap_file, display_filter='rtp')
    
    # Process RTP packets
    for packet in capture:
        try:
            # Extract RTP payload
            rtp_layer = packet.rtp
            payload = bytes.fromhex(rtp_layer.payload.replace(':', ''))
            
            # Create stream key
            stream_key = (
                packet.ip.src, 
                packet.ip.dst, 
                packet.udp.srcport, 
                packet.udp.dstport
            )
            
            # Initialize or append to stream
            if stream_key not in rtp_streams:
                rtp_streams[stream_key] = []
            rtp_streams[stream_key].append(payload)
        
        except Exception as e:
            print(f"Packet processing skipped: {e}")
    
    # Find longest stream
    if not rtp_streams:
        print("No RTP streams found.")
        return
    
    longest_stream = max(rtp_streams.values(), key=len)
    
    # Decode OPUS packets
    audio_samples = []
    
    # Multiple decoder attempts
    decoder_modes = [
        (48000, 1),   # Standard mono
        (48000, 2),   # Stereo
        (16000, 1),   # Lower sample rate
        (8000, 1)     # Lowest sample rate
    ]
    
    for sample_rate, channels in decoder_modes:
        try:
            decoder = opuslib.Decoder(sample_rate, channels)
            temp_samples = []
            
            for payload in longest_stream:
                try:
                    # Try decoding with different frame sizes
                    for frame_size in [960, 480, 240]:
                        try:
                            decoded_frame = decoder.decode(payload, frame_size, decode_fec=True)
                            temp_samples.extend(np.frombuffer(decoded_frame, dtype=np.int16))
                            break
                        except Exception:
                            continue
                
                except Exception as e:
                    print(f"Individual payload decoding error: {e}")
            
            # If we successfully decoded some samples, use them
            if temp_samples:
                audio_samples = temp_samples
                print(f"Successfully decoded with {sample_rate}Hz, {channels} channels")
                break
        
        except Exception as e:
            print(f"Decoder initialization error: {e}")
    
    # Write audio file
    if audio_samples:
        sf.write(output_file, np.array(audio_samples), 48000)
        print(f"Audio extracted to {output_file}")
    else:
        print("No audio samples decoded.")

# Usage example
extract_voip_audio('1.pcap', 'extracted_audio_us.wav')