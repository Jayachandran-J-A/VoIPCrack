import pyshark
import ipaddress
import requests
from datetime import datetime
import pycountry

def is_private_ip(ip):
    """Check if the IP address is private."""
    private_ranges = [
        "10.", "172.16.", "192.168."
    ]
    return any(ip.startswith(prefix) for prefix in private_ranges) or ipaddress.ip_address(ip).is_private

def get_public_ip():
    """Fetch the public IP address of the user."""
    try:
        response = requests.get("https://api64.ipify.org?format=json")
        response.raise_for_status()
        return response.json().get("ip")
    except requests.RequestException as e:
        print(f"Error fetching public IP: {e}")
        return None

def get_geolocation(ip):
    """Get geolocation data for a given IP address."""
    api_key = "2692c6877bb8bd"  # Replace with your geolocation API key
    url = f"https://ipinfo.io/{ip}/json?token={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching geolocation data: {e}")
        return None

def get_location_from_ip(ip):
    try:
        if is_private_ip(ip):
            ip = get_public_ip()
            if not ip:
                return "Local Network (Unable to determine public IP)"
        
        location_data = get_geolocation(ip)
        if location_data:
            city = location_data.get("city", "Unknown")
            region = location_data.get("region", "Unknown")
            country_code = location_data.get("country", "Unknown")
            country_name = pycountry.countries.get(alpha_2=country_code).name if pycountry.countries.get(alpha_2=country_code) else "Unknown Country"
            return f"{city}, {region}, {country_name} ({country_code})"

        return "Unknown Location"
    except Exception as e:
        return f"Error locating {ip}: {e}"

def get_ip_addresses(packet):
    """
    Extract source and destination IP addresses from packet, handling both IPv4 and IPv6.
    Returns tuple of (source_ip, dest_ip)
    """
    from_ip = to_ip = 'N/A'

    if hasattr(packet, 'ipv6'):
        from_ip = packet.ipv6.src
        to_ip = packet.ipv6.dst
    elif hasattr(packet, 'ip'):
        from_ip = packet.ip.src
        to_ip = packet.ip.dst

    return from_ip, to_ip

def extract_codec_details(pcap_file):
    """Extract codec details from the SIP layer."""
    extracted_fields = {
        'sdp.media.proto': set(),
        'sdp.media.format': set(),
        'sdp.mime.type': set(),
        'sdp.sample_rate': set()
    }

    cap = pyshark.FileCapture(pcap_file, display_filter='sip and sdp')

    for packet in cap:
        if hasattr(packet, 'sip'):
            # Extract specific fields
            media_proto = packet.sip._all_fields.get('sdp.media.proto', None)
            media_format = packet.sip._all_fields.get('sdp.media.format', None)
            mime_type = packet.sip._all_fields.get('sdp.mime.type', None)
            sample_rate = packet.sip._all_fields.get('sdp.sample_rate', None)

            if media_proto:
                extracted_fields['sdp.media.proto'].add(media_proto)
            if media_format:
                extracted_fields['sdp.media.format'].add(media_format)
            if mime_type:
                extracted_fields['sdp.mime.type'].add(mime_type)
            if sample_rate:
                extracted_fields['sdp.sample_rate'].add(sample_rate)

    cap.close()
    return extracted_fields

def extract_sip_summary(pcap_file):
    sip_summary = {
        'ip_summary': {
            'date': None,
            'start_time': None,
            'end_time': None,
            'duration': None
        },
        'codec_details': [],
        'calls': {}
    }

    cap = pyshark.FileCapture(pcap_file, display_filter='sip')

    for packet in cap:
        try:
            sniff_time = packet.sniff_time
            if not sip_summary['ip_summary']['date']:
                sip_summary['ip_summary']['date'] = sniff_time.date()
                sip_summary['ip_summary']['start_time'] = sniff_time.time()
            sip_summary['ip_summary']['end_time'] = sniff_time.time()

            if hasattr(packet, 'sip'):
                sip_layer = packet.sip
                call_id = sip_layer.get('call-id', 'unknown_call_id')

                from_ip, to_ip = get_ip_addresses(packet)
                from_location = get_location_from_ip(from_ip) if from_ip != 'N/A' else "Unknown Location"
                to_location = get_location_from_ip(to_ip) if to_ip != 'N/A' else "Unknown Location"

                if call_id not in sip_summary['calls']:
                    sip_summary['calls'][call_id] = {
                        'from': {
                            'user': sip_layer.get('from_user', '').replace('%20', ' '),
                            'addr': sip_layer.get('from_addr', '').replace('%20', ' '),
                        },
                        'to': {
                            'user': sip_layer.get('to_user', '').replace('%20', ' '),
                            'addr': sip_layer.get('to_addr', '').replace('%20', ' '),
                        },
                        'ips': {'from': from_ip, 'to': to_ip},
                        'locations': {'from': from_location, 'to': to_location},
                    }

        except Exception as e:
            print(f"Processing error for packet {packet.number}: {e}")

    cap.close()
    codec_details = extract_codec_details(pcap_file)
    for proto in codec_details['sdp.media.proto']:
        for fmt in codec_details['sdp.media.format']:
            for mime in codec_details['sdp.mime.type']:
                for rate in codec_details['sdp.sample_rate']:
                    sip_summary['codec_details'].append({
                        'protocol': proto,
                        'media_format': fmt,
                        'codec': mime,
                        'sample_rate': rate
                    })
    # Calculate duration
    if sip_summary['ip_summary']['start_time'] and sip_summary['ip_summary']['end_time']:
        start_time = datetime.combine(sip_summary['ip_summary']['date'], sip_summary['ip_summary']['start_time'])
        end_time = datetime.combine(sip_summary['ip_summary']['date'], sip_summary['ip_summary']['end_time'])
        duration = end_time - start_time
        sip_summary['ip_summary']['duration'] = duration

    print(f"Date: {sip_summary['ip_summary']['date']}")
    print(f"Start Time: {sip_summary['ip_summary']['start_time']}")
    print(f"End Time: {sip_summary['ip_summary']['end_time']}")
    print(f"Call Duration: {sip_summary['ip_summary']['duration']}")

    print("\nCall Details:")
    for call_id, call_details in sip_summary['calls'].items():
        print(f"\nCall ID: {call_id}")
        print("From:")
        print(f"  User: {call_details['from']['user']}")
        print(f"  Address: {call_details['from']['addr']}")
        print(f"  IP: {call_details['ips']['from']}")
        print(f"  Location: {call_details['locations']['from']}")

        print("\nTo:")
        print(f"  User: {call_details['to']['user']}")
        print(f"  Address: {call_details['to']['addr']}")
        print(f"  IP: {call_details['ips']['to']}")
        print(f"  Location: {call_details['locations']['to']}")

    print("\nCodec Details:")
    if not sip_summary['codec_details']:
        print("No codec details found.")
    for codec in sip_summary['codec_details']:
        print(f"Protocol: {codec['protocol']}")
        print(f"Media Format: {codec['media_format']}")
        print(f"Codec: {codec['codec']}")
        print(f"Sample Rate: {codec['sample_rate']} Hz")

    return sip_summary

if __name__ == "__main__":
    pcap_file_path = input("Enter the path to the PCAP file: ").strip()
    if pcap_file_path:
        extract_sip_summary(pcap_file_path)
    else:
        print("No file path provided. Exiting...")
