import pyshark
import argparse
from pathlib import Path
import os

def filter_voip_traffic(input_file, output_file):
    """
    Filter VoIP traffic from input pcap/pcapng file and save to a new file.
    
    Args:
        input_file (str): Path to input capture file
        output_file (str): Path to save filtered capture file
    """
    # Simple VoIP display filter
    display_filter = "sip or rtp"
    
    # Create capture objects
    capture = pyshark.FileCapture(input_file)
    output_capture = pyshark.FileCapture(
        input_file,
        display_filter=display_filter,
        output_file=output_file
    )
    
    try:
        total_packets = 0
        voip_packets = 0
        
        print(f"Processing {input_file}...")
        
        # Process filtered packets
        for packet in output_capture:
            voip_packets += 1
            
        # Count total packets
        for _ in capture:
            total_packets += 1
        
        print(f"\nProcessing complete!")
        print(f"Total packets processed: {total_packets}")
        print(f"VoIP packets filtered: {voip_packets}")
        print(f"Removed packets: {total_packets-voip_packets}")
        print(f"Filtered capture saved to: {output_file}")
        
    except Exception as e:
        print(f"Error during processing: {str(e)}")
        raise
        
    finally:
        capture.close()
        output_capture.close()

def main():
    parser = argparse.ArgumentParser(description='Filter VoIP traffic from pcap/pcapng files')
    parser.add_argument('input_file', help='Input capture file (pcap/pcapng)')
    parser.add_argument('output_file', help='Output file to save filtered traffic')
    args = parser.parse_args()
    
    # Validate input file exists
    if not Path(args.input_file).exists():
        print(f"Error: Input file '{args.input_file}' not found!")
        return
    
    # Remove output file if it exists
    if os.path.exists(args.output_file):
        os.remove(args.output_file)
    
    filter_voip_traffic(args.input_file, args.output_file)

if __name__ == '__main__':
    main()
