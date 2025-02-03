import os
import sys
import pyshark
import numpy as np
import soundfile as sf
import subprocess
import audioop
import opuslib
from collections import defaultdict

class VoIPAudioExtractor:
    def __init__(self, pcap_file, output_file='output.wav'):
        self.pcap_file = pcap_file
        self.output_file = output_file
        self.rtp_streams = defaultdict(list)
        self.codec = None

    def extract_codec_type(self):
        """Determine codec type from SIP/SDP information."""
        try:
            capture = pyshark.FileCapture(self.pcap_file, display_filter='sip and sdp')
            for packet in capture:
                if hasattr(packet, 'sip'):
                    codec = packet.sip._all_fields.get('sdp.mime.type', None)
                    if codec:
                        self.codec = codec.lower()
                        capture.close()
                        return self.codec
            capture.close()
        except Exception as e:
            print(f"Codec detection error: {e}")
        return None

    def extract_rtp_streams(self):
        """Extract RTP streams from PCAP file."""
        try:
            capture = pyshark.FileCapture(
                self.pcap_file, 
                display_filter='rtp and udp',
                only_summaries=False
            )
            for packet in capture:
                try:
                    rtp_layer = packet.rtp
                    payload = bytes.fromhex(rtp_layer.payload.replace(':', ''))
                    
                    src_ip = packet.ip.src if hasattr(packet, 'ip') else packet.ipv6.src
                    dst_ip = packet.ip.dst if hasattr(packet, 'ip') else packet.ipv6.dst
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport
                    
                    stream_key = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")
                    self.rtp_streams[stream_key].append({
                        'seq': int(rtp_layer.seq),
                        'timestamp': int(rtp_layer.timestamp),
                        'payload': payload
                    })
                except Exception as e:
                    pass
            capture.close()
        except Exception as e:
            print(f"RTP stream extraction error: {e}")
        return self.rtp_streams

    def decode_opus(self):
        """Decode Opus codec audio streams."""
        sample_rates = [48000, 24000, 16000, 12000, 8000]
        channel_configs = [(1, 'mono'), (2, 'stereo')]
        
        for sample_rate in sample_rates:
            for channels, channel_name in channel_configs:
                try:
                    decoder = opuslib.Decoder(sample_rate, channels)
                    decoded_streams = []
                    
                    for stream_key, packets in self.rtp_streams.items():
                        sorted_packets = sorted(packets, key=lambda x: (x['timestamp'], x['seq']))
                        audio_samples = []
                        
                        for packet in sorted_packets:
                            for frame_size in [960, 480, 240, 120]:
                                try:
                                    decoded_frame = decoder.decode(packet['payload'], frame_size, decode_fec=True)
                                    audio_samples.extend(np.frombuffer(decoded_frame, dtype=np.int16))
                                    break
                                except Exception:
                                    continue
                        
                        if audio_samples:
                            decoded_streams.append(np.array(audio_samples))
                    
                    if decoded_streams:
                        return self._synchronize_streams(decoded_streams, sample_rate)
                except Exception:
                    continue
        return None

    def decode_g729(self):
        """Decode G.729 codec audio streams."""
        decoded_streams = []
        for stream_key, packets in self.rtp_streams.items():
            try:
                sorted_packets = sorted(packets, key=lambda x: x['seq'])
                g729_data = b''.join(packet['payload'] for packet in sorted_packets)
                
                with open('temp.g729', 'wb') as f:
                    f.write(g729_data)
                
                subprocess.run([
                    "ffmpeg", "-y", "-f", "g729", "-i", "temp.g729", "output_temp.wav"
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                
                audio, _ = sf.read("output_temp.wav", dtype='int16')
                decoded_streams.append(audio)
            
            except Exception as e:
                print(f"Stream processing error: {e}")
        
        self._cleanup_temp_files(['temp.g729', 'output_temp.wav'])
        return self._synchronize_streams(decoded_streams)

    def decode_gsm(self):
        """Decode GSM codec audio streams."""
        decoded_streams = []
        for stream_key, packets in self.rtp_streams.items():
            try:
                sorted_packets = sorted(packets, key=lambda x: x['seq'])
                gsm_data = b''.join(packet['payload'] for packet in sorted_packets)
                
                with open('temp.gsm', 'wb') as f:
                    f.write(gsm_data)
                
                subprocess.run([
                    "ffmpeg", "-y", "-f", "gsm", "-i", "temp.gsm", "output_temp.wav"
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                
                audio, _ = sf.read("output_temp.wav", dtype='int16')
                decoded_streams.append(audio)
            
            except Exception as e:
                print(f"Stream processing error: {e}")
        
        self._cleanup_temp_files(['temp.gsm', 'output_temp.wav'])
        return self._synchronize_streams(decoded_streams)

    def decode_pcma(self):
        """Decode PCMA (A-law) codec audio streams."""
        return self._decode_alaw_ulaw('alaw')

    def decode_pcmu(self):
        """Decode PCMU (μ-law) codec audio streams."""
        return self._decode_alaw_ulaw('ulaw')

    def _decode_alaw_ulaw(self, codec_type):
        """Generic A-law and μ-law decoding method."""
        decoded_streams = []
        for stream_key, packets in self.rtp_streams.items():
            try:
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
                            decoded = audioop.alaw2lin(chunk, 2) if codec_type == 'alaw' else audioop.ulaw2lin(chunk, 2)
                            stream_samples.extend(np.frombuffer(decoded, dtype=np.int16))
                        except Exception as e:
                            print(f"Decoding error: {e}")
                
                if stream_samples:
                    samples_array = np.array(stream_samples, dtype=np.float32)
                    if np.max(np.abs(samples_array)) > 0:
                        samples_array = samples_array / np.max(np.abs(samples_array)) * 32767
                    decoded_streams.append(samples_array.astype(np.int16))
            
            except Exception as e:
                print(f"Stream processing error: {e}")
        
        return self._synchronize_streams(decoded_streams)

    def _synchronize_streams(self, decoded_streams, sample_rate=8000):
        """Synchronize and merge decoded audio streams."""
        if not decoded_streams:
            return False
        
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
        
        sf.write(self.output_file, final_audio, sample_rate)
        print(f"Audio extracted to {self.output_file}")
        return True

    def _cleanup_temp_files(self, files):
        """Clean up temporary files."""
        for temp_file in files:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def extract_audio(self):
        """Main method to extract audio from PCAP file."""
        # Determine codec type
        self.codec = self.extract_codec_type()
        if not self.codec:
            print("Unable to determine codec type.")
            return False
        
        # Extract RTP streams
        self.rtp_streams = self.extract_rtp_streams()
        if not self.rtp_streams:
            print("No RTP streams found.")
            return False
        
        # Decode based on codec
        try:
            if self.codec == 'opus':
                return self.decode_opus()
            elif self.codec == 'g729':
                return self.decode_g729()
            elif self.codec == 'gsm':
                return self.decode_gsm()
            elif self.codec == 'pcma':
                return self.decode_pcma()
            elif self.codec == 'pcmu':
                return self.decode_pcmu()
            else:
                print(f"Unsupported codec: {self.codec}")
                return False
        except Exception as e:
            print(f"Audio extraction error: {e}")
            return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python voip_audio_extractor.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    extractor = VoIPAudioExtractor(pcap_file)
    extractor.extract_audio()

if __name__ == "__main__":
    main()
