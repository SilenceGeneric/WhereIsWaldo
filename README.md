# WhereIsWaldo - Network Monitoring & Geolocation Tool

WhereIsWaldo is a powerful and easy-to-use network monitoring and geolocation tool. It helps you capture network packets, trace IP addresses, and get detailed geolocation information on live network traffic. This tool is built to be used in a controlled environment (like your classroom or lab) to help understand network traffic and IP tracing.

## Features:
- **Capture Network Packets:** Sniff and capture network packets on any network interface.
- **IP Address Geolocation:** Automatically fetches geolocation information for IP addresses using the GeoLite2 database.
- **Protocol-specific Information:** Displays detailed information for different protocols like TCP, UDP, and ICMP.
- **Packet Filtering:** Filter packets based on IP address, port, and protocol.
- **Save Captured Packets:** Option to save captured packets in PCAP format for further analysis.
- **Automatic Database Updates:** Keeps the GeoLite2 database up-to-date for accurate geolocation information.
- **Command-Line Interface:** Use simple command-line arguments to filter and control the sniffing process.

## Requirements:
- **Python 3.x**: Make sure you have Python 3 or later installed.
- **Libraries**: The script will automatically install the required libraries when you run it.

## Setup Instructions:

1. **Download the repository**:
   Clone this repository to your local machine using:
   ```bash
   git clone https://github.com/SilenceGeneric/WhereIsWaldo.git
   ```

2. **Install Dependencies**:
   The script will automatically install any required dependencies when you run it. Just make sure you have Python 3 installed, and it will handle the rest.

3. **Download GeoLite2 Database**:
   The tool will automatically download the GeoLite2 City database the first time you run it. This database is needed for accurate geolocation.

4. **Running the Script**:
   Open a terminal and navigate to the folder where the script is located. Run the following command:
   ```bash
   python3 WhereIsWaldo.py --interface <network_interface> --pcap-file output.pcap
   ```

   Replace `<network_interface>` with the name of your network interface (e.g., `eth0`, `wlan0`). This will start sniffing network packets on that interface and saving them to the file `output.pcap`.

   You can also filter packets by IP, port, and protocol using optional command-line arguments. For example:
   ```bash
   python3 WhereIsWaldo.py --interface eth0 --ip-src-filter 192.168.1.1 --pcap-file output.pcap
   ```

## Features and Arguments:
- `--interface <interface>`: Specify the network interface to sniff on (e.g., `eth0`, `wlan0`).
- `--ip-src-filter <ip>`: Filter packets by source IP address.
- `--ip-dst-filter <ip>`: Filter packets by destination IP address.
- `--port-src-filter <port>`: Filter packets by source port.
- `--port-dst-filter <port>`: Filter packets by destination port.
- `--protocol-filter <protocol>`: Filter packets by protocol (1=ICMP, 6=TCP, 17=UDP).
- `--pcap-file <file>`: Specify the file to save captured packets (default is `output.pcap`).

## Geolocation:
The tool uses the GeoLite2 database for IP geolocation. This database is updated periodically, and the script will automatically download the latest version of the database if needed.

## Ethics and Legal Considerations:
**Important**: Ensure that you have explicit permission to capture network traffic before running this tool. The tool is intended for educational and ethical security research purposes. Always comply with the laws and regulations in your region.

## Notes:
- The tool is designed to be used in controlled environments like a classroom, lab, or personal network for educational purposes.
- It works in the wild but should only be used on networks you have permission to monitor.
- If you plan to take it outside the classroom, ensure that you're following all relevant privacy and ethical guidelines.

## License:
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
