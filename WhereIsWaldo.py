import subprocess
import sys
import os
import logging
import psutil
import socket
import requests

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to check and install required dependencies automatically
def install_dependencies():
    venv_dir = "venv"
    # Check if the virtual environment exists, if not, create it
    if not os.path.exists(venv_dir):
        logging.info("Creating virtual environment...")
        subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
    
    # Install dependencies if not already installed
    try:
        subprocess.check_call([os.path.join(venv_dir, "bin", "pip"), "install", "--upgrade", "pip"])
        subprocess.check_call([os.path.join(venv_dir, "bin", "pip"), "install", "psutil", "requests"])
    except subprocess.CalledProcessError as e:
        logging.error(f"Error installing dependencies: {e}")
        sys.exit(1)

# Get live IP addresses from active network connections
def get_live_ips():
    """Get IP addresses from live network sessions."""
    live_ips = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            ip = conn.raddr.ip if conn.raddr else None
            if ip and ip not in live_ips:
                live_ips.append(ip)
    except Exception as e:
        logging.error(f"Error fetching live IP addresses: {e}")
        logging.debug(e)
    return live_ips

# Resolve hostnames for live IP addresses
def resolve_hostnames(live_ips):
    """Resolve hostnames for live IP addresses."""
    ip_hostname_map = {}
    for ip in live_ips:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            ip_hostname_map[ip] = hostname
        except (socket.herror, socket.gaierror) as e:
            ip_hostname_map[ip] = None  # If resolution fails, store None
            logging.warning(f"Failed to resolve hostname for IP {ip}: {e}")
    return ip_hostname_map

# Trace the route to a specific IP address
def trace_route(ip):
    """Trace the route to a specific IP address."""
    try:
        result = subprocess.check_output(["traceroute", ip], stderr=subprocess.STDOUT)
        result = result.decode("utf-8")
        return result
    except subprocess.CalledProcessError as e:
        logging.error(f"Error tracing route to IP {ip}: {e}")
        return None

# Geolocate an IP address
def geolocate_ip(ip):
    """Geolocate an IP address using an external service."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'fail':
            return None
        return {
            "IP": ip,
            "Country": data.get('country', 'N/A'),
            "Region": data.get('regionName', 'N/A'),
            "City": data.get('city', 'N/A'),
            "Latitude": data.get('lat', 'N/A'),
            "Longitude": data.get('lon', 'N/A'),
            "ISP": data.get('isp', 'N/A')
        }
    except requests.RequestException as e:
        logging.error(f"Error geolocating IP {ip}: {e}")
        return None

# Main execution
if __name__ == "__main__":
    # Install required dependencies before proceeding
    install_dependencies()

    try:
        # Get live IP addresses from active network connections
        live_ips = get_live_ips()
        logging.info(f"Live IP addresses found: {live_ips}")

        if live_ips:
            # Resolve hostnames for the live IP addresses
            ip_hostname_map = resolve_hostnames(live_ips)
            for ip, hostname in ip_hostname_map.items():
                logging.info(f"IP: {ip} | Hostname: {hostname}")

            # Trace the route to each live IP address
            for ip in live_ips:
                trace_result = trace_route(ip)
                if trace_result:
                    logging.info(f"Traceroute result for {ip}:\n{trace_result}")

            # Geolocate the IP addresses
            for ip in live_ips:
                geo_info = geolocate_ip(ip)
                if geo_info:
                    logging.info(f"Geolocation for {ip}: {geo_info}")
                else:
                    logging.warning(f"Geolocation not available for {ip}")
        else:
            logging.info("No live IP addresses found.")
            
    except Exception as e:
        logging.error("An error occurred.")
        logging.debug(e)
