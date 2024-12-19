import subprocess
import sys
import os
import re
import requests


def run_command(command):
    #print(f"Running command: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running command: {result.stderr}")
        sys.exit(1)
    return result.stdout

def extract_sip_info(pcap_file):
    print("Extracting SIP information...")
    command = f"sudo tshark -r {pcap_file} -Y 'sip' -T fields -e sip.From -e sip.To -e sip.Contact -e ip.src -e ip.dst -e ip.proto"
    output = run_command(command)
    return output


def parse_sip_info(output):
    call_info = []
    seen = set()  # To track and avoid duplicates
    lines = output.strip().splitlines()

    for line in lines:
        fields = line.split('\t')
        if len(fields) >= 5:
            # Extracting caller ID (sip.from), callee ID (sip.to), and their respective IPs
            caller_id = fields[0]
            callee_id = fields[1]
            caller_ip = fields[3]  
            callee_ip = fields[4] 
            transport_proto = fields[5] 
            
            caller_domain = extract_domain(caller_id)
            callee_domain = extract_domain(callee_id)
            
            if (caller_id, callee_id, caller_ip, callee_ip) not in seen:
                seen.add((caller_id, callee_id, caller_ip, callee_ip))
                
                # Store the parsed data
                call_info.append({
                    'caller_id': caller_id,
                    'callee_id': callee_id,
                    'caller_ip': caller_ip,
                    'callee_ip': callee_ip,
                    'caller_domain': caller_domain,
                    'callee_domain': callee_domain,
                    'transport_proto': transport_proto
                })

    return call_info

# Function to extract the domain from a SIP ID (e.g., from sip:1001@domain.com -> domain.com)
def extract_domain(sip_id):
    match = re.search(r'@([^\s;]+)', sip_id)
    if match:
        return match.group(1)
    return "N/A"  # Default if no domain found

def fetch_location(ip_address):
    try:
        #print(f"Fetching location for IP: {ip_address}")
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")  # Replace with your preferred API
        if response.status_code == 200:
            data = response.json()
            location = data.get('city', 'Unknown') + ", " + data.get('region', 'Unknown') + ", " + data.get('country', 'Unknown')
            return location
        else:
            print(f"Failed to fetch location for {ip_address}: {response.status_code}")
    except Exception as e:
        print(f"Error fetching location for {ip_address}: {e}")
    return "Location unavailable"

def save_and_display_info(call_info):
    with open('call_info.txt', 'w') as f:
        for info in call_info:
            # Fetch geolocation for caller and callee IPs
            caller_location = fetch_location(info['caller_ip'])
            callee_location = fetch_location(info['callee_ip'])

            # Write data to file
            f.write(f"Caller ID: {info['caller_id']}\n")
            f.write(f"Caller IP: {info['caller_ip']}\n")
            f.write(f"Caller Location: {caller_location}\n")
            f.write(f"Caller Domain: {info['caller_domain']}\n")
            f.write(f"Callee ID: {info['callee_id']}\n")
            f.write(f"Callee IP: {info['callee_ip']}\n")
            f.write(f"Callee Location: {callee_location}\n")
            f.write(f"Callee Domain: {info['callee_domain']}\n")
            f.write(f"Transport: {info['transport_proto']}\n")
            f.write("-" * 50 + "\n")

    print("Analysis complete.")
    print("Caller and Callee information saved in call_info.txt")

# Main function to process the pcap file
def process_pcap(pcap_file):
    if not os.path.exists(pcap_file):
        print(f"Error: The file {pcap_file} does not exist.")
        sys.exit(1)

    # Step 1: Extract SIP information (caller ID, callee ID, IP addresses, transport protocol)
    raw_output = extract_sip_info(pcap_file)

    # Step 2: Parse the raw output to extract caller and callee details
    call_info = parse_sip_info(raw_output)

    # Step 3: Save and display the extracted information
    save_and_display_info(call_info)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_voip.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    process_pcap(pcap_file)