import pyshark
import ipaddress
import subprocess

def get_location_from_ip(ip):
    try:
        # Check if IP is private or loopback
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return {'city': 'Local', 'country': 'Internal Network'}

        # Use `whois` to find the location
        whois_output = subprocess.run(['whois', ip], capture_output=True, text=True)
        if whois_output.returncode == 0:
            output_lines = whois_output.stdout.splitlines()
            country = city = 'Unknown'
            for line in output_lines:
                if line.lower().startswith('country:'):
                    country = line.split(':', 1)[1].strip()
                elif line.lower().startswith('city:'):
                    city = line.split(':', 1)[1].strip()
            return {'city': city, 'country': country}

        return {'city': 'Unknown', 'country': 'Unknown'}
    except Exception as e:
        return {'city': 'Unknown', 'country': f'Error locating {ip}'}

def extract_specific_sdp_fields(pcap_file):
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
            'end_time': None
        },
        'calls': {},
        'codec_details': []
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
                from_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
                to_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
                from_location = get_location_from_ip(from_ip)
                to_location = get_location_from_ip(to_ip)

                if call_id not in sip_summary['calls']:
                    sip_summary['calls'][call_id] = {
                        'from': {
                            'user': sip_layer.get('from_user', ''),
                            'addr': sip_layer.get('from_addr', ''),
                        },
                        'to': {
                            'user': sip_layer.get('to_user', ''),
                            'addr': sip_layer.get('to_addr', ''),
                        },
                        'ips': {'from': from_ip, 'to': to_ip},
                        'geolocation': {
                            'from': {'city': from_location['city'], 'country': from_location['country']},
                            'to': {'city': to_location['city'], 'country': to_location['country']},
                        }
                    }

        except Exception as e:
            print(f"Processing error for packet {packet.number}: {e}")

    cap.close()

    # Extract codec details
    codec_details = extract_specific_sdp_fields(pcap_file)
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

    # Print summary
    print(f"Date: {sip_summary['ip_summary']['date']}")
    print(f"Start Time: {sip_summary['ip_summary']['start_time']}")
    print(f"End Time: {sip_summary['ip_summary']['end_time']}")

    print("\nCall Details:")
    for call_id, call_details in sip_summary['calls'].items():
        print(f"\nCall ID: {call_id}")

        print("From:")
        print(f"  User: {call_details['from']['user']}")
        print(f"  Address: {call_details['from']['addr']}")
        print(f"  IP: {call_details['ips']['from']}")
        print(f"  Location: {call_details['geolocation']['from']['country']}, {call_details['geolocation']['from']['city']}")

        print("\nTo:")
        print(f"  User: {call_details['to']['user']}")
        print(f"  Address: {call_details['to']['addr']}")
        print(f"  IP: {call_details['ips']['to']}")
        print(f"  Location: {call_details['geolocation']['to']['country']}, {call_details['geolocation']['to']['city']}")

    print("\nCodec Details:")
    if not sip_summary['codec_details']:
        print("No codec details found.")
    for codec in sip_summary['codec_details']:
        print(f"Protocol: {codec['protocol']}")
        print(f"Media Format: {codec['media_format']}")
        print(f"Codec: {codec['codec']}")
        print(f"Sample Rate: {codec['sample_rate']} Hz")
    return sip_summary

# Main entry point
if __name__ == "__main__":
    # Prompt user for the PCAP file path
    pcap_file_path = input("Enter the path to the PCAP file: ").strip()
    if pcap_file_path:
        extract_sip_summary(pcap_file_path)
    else:
        print("No file path provided. Exiting...")
