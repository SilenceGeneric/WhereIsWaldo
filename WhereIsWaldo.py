import subprocess
import sys
import os
import geoip2.database
import psutil
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
import logging
import argparse
import chardet
import urllib.request
import zipfile
import time

# Function to install missing dependencies
def install_dependencies():
    required_libraries = ['scapy', 'geoip2', 'psutil', 'chardet']
    for library in required_libraries:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", library])
        except subprocess.CalledProcessError as e:
            print(f"Failed to install {library}: {e}")
            sys.exit(1)

# Function to download the GeoLite2 database
def download_geolite2():
    geoip_url = "https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz"
    geoip_filename = "GeoLite2-City.tar.gz"

    # Check if database exists and if it is outdated
    if not os.path.exists("GeoLite2-City.mmdb") or is_database_outdated():
        print("Downloading GeoLite2 City database...")
        urllib.request.urlretrieve(geoip_url, geoip_filename)

        # Extract the tar.gz file
        print("Extracting GeoLite2 database...")
        with zipfile.ZipFile(geoip_filename, 'r') as zip_ref:
            zip_ref.extractall()

# Function to check if the GeoLite2 database is outdated (older than 30 days)
def is_database_outdated():
    try:
        database_mtime = os.path.getmtime("GeoLite2-City.mmdb")
        current_time = time.time()
        # Check if the database is older than 30 days (2592000 seconds)
        return current_time - database_mtime > 2592000
    except FileNotFoundError:
        return True

# Install dependencies and download the database if needed
install_dependencies()
download_geolite2()

# Logging setup
logging.basicConfig(level=logging.INFO)

# Function to fetch geolocation data from MaxMind's GeoLite2 database
def get_geolocation(ip):
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')  # GeoLite2 database file
        response = reader.city(ip)
        return {
            'ip': ip,
            'city': response.city.name if response.city.name else 'N/A',
            'country': response.country.name if response.country.name else 'N/A',
            'location': (response.location.latitude, response.location.longitude)
        }
    except geoip2.errors.AddressNotFoundError:
        return None

# Function to list all available network interfaces
def list_interfaces():
    interfaces = psutil.net_if_addrs()
    for interface in interfaces:
        print(f"Interface: {interface}")

# Function to decode raw packet data
def decode_raw_data(packet):
    if hasattr(packet.payload, 'original'):
        raw_data = packet.payload.original
        detection = chardet.detect(raw_data)
        encoding = detection['encoding']
        try:
            decoded_data = raw_data.decode(encoding, errors='ignore')
            return decoded_data
        except:
            return "Decoding error"
    return "No payload"

# Function to capture packets and filter by IP, port, and protocol
def capture_packets(packet, pcap_file, ip_src_filter=None, ip_dst_filter=None, port_src_filter=None, port_dst_filter=None, protocol_filter=None):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet.getlayer(IP).proto
        ttl = packet[IP].ttl
        raw_data = decode_raw_data(packet)

        # Apply filters if set
        if ip_src_filter and ip_src != ip_src_filter:
            return
        if ip_dst_filter and ip_dst != ip_dst_filter:
            return
        if port_src_filter:
            if packet.haslayer(TCP) and packet[TCP].sport != port_src_filter:
                return
            if packet.haslayer(UDP) and packet[UDP].sport != port_src_filter:
                return
        if port_dst_filter:
            if packet.haslayer(TCP) and packet[TCP].dport != port_dst_filter:
                return
            if packet.haslayer(UDP) and packet[UDP].dport != port_dst_filter:
                return
        if protocol_filter and proto != protocol_filter:
            return

        # Log packet information
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            seq_num = packet[TCP].seq
            ack_num = packet[TCP].ack
            window_size = packet[TCP].window
            logging.info(f"Packet from {ip_src} to {ip_dst} - Proto: {proto} - TTL: {ttl} - Flags: {flags} - Seq: {seq_num} - Ack: {ack_num} - Window: {window_size}")
        else:
            logging.info(f"Packet from {ip_src} to {ip_dst} - Proto: {proto} - TTL: {ttl}")
        logging.info(f"Raw Data (Decoded): {raw_data[:100]}...")  # Display the first 100 chars of the raw data

        # Geolocation information
        geolocation = get_geolocation(ip_src)
        if geolocation:
            logging.info(f"Geolocation for {ip_src}: {geolocation['city']}, {geolocation['country']} - Location: {geolocation['location']}")
        else:
            logging.info(f"Geolocation for {ip_src} not found")

        # Save packet to PCAP
        wrpcap(pcap_file, packet, append=True)

# Function to start sniffing packets with command-line arguments for filtering
def start_sniffing(interface, pcap_file, ip_src_filter=None, ip_dst_filter=None, port_src_filter=None, port_dst_filter=None, protocol_filter=None):
    if interface not in psutil.net_if_addrs():
        logging.error(f"Interface {interface} not found.")
        return
    logging.info(f"Starting sniffing on {interface}...")
    sniff(iface=interface, prn=lambda packet: capture_packets(packet, pcap_file, ip_src_filter, ip_dst_filter, port_src_filter, port_dst_filter, protocol_filter), store=0)

# Main function to handle command-line arguments and run the program
def main():
    # Command-line argument parsing
    parser = argparse.ArgumentParser(description="Network Packet Sniffer and Geolocation Tool")
    parser.add_argument('--interface', type=str, required=True, help='Network interface to sniff (e.g., eth0)')
    parser.add_argument('--ip-src-filter', type=str, help='Filter packets by source IP')
    parser.add_argument('--ip-dst-filter', type=str, help='Filter packets by destination IP')
    parser.add_argument('--port-src-filter', type=int, help='Filter packets by source port')
    parser.add_argument('--port-dst-filter', type=int, help='Filter packets by destination port')
    parser.add_argument('--protocol-filter', type=int, choices=[1, 6, 17], help='Filter packets by protocol (1=ICMP, 6=TCP, 17=UDP)')
    parser.add_argument('--pcap-file', type=str, default="output.pcap", help="File to save packet capture")

    args = parser.parse_args()

    # List network interfaces (optional)
    list_interfaces()

    # Start sniffing
    start_sniffing(args.interface, args.pcap_file, args.ip_src_filter, args.ip_dst_filter, args.port_src_filter, args.port_dst_filter, args.protocol_filter)

if __name__ == "__main__":
    main()
