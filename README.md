# WhereIsWaldo
Advanced ip tracer, geolocation, and other info from live platforms.

WhereIsWaldo is a Python-based IP tracking and network analysis tool designed for Linux (Debian/Ubuntu). The program allows you to track and geolocate an IP address, randomize MAC addresses for privacy, and provides detailed information such as ISP, ASN, and geographic coordinates.

## Features

- **IP Tracking**: Allows you to enter an IP address and retrieve detailed location and network information.
- **MAC Address Randomization**: Provides the ability to randomize your MAC address to ensure privacy.
- **GeoLocation**: Fetches geolocation data including city, country, latitude, longitude, ISP, and ASN information.
- **Cross-Platform (Linux)**: Runs on Debian/Ubuntu systems, ensuring compatibility with most Linux environments.
- **Automatic Dependency Installation**: The program automatically installs required dependencies if they are missing.
- **User-Friendly Interface**: A simple GUI built using Tkinter to allow users to easily input IP addresses and view results.

## Requirements

- **Operating System**: Debian or Ubuntu Linux (other systems are not supported).
- **Python 3**: The program is written in Python and requires Python 3 to run.
- **Dependencies**: The script automatically installs the following dependencies if not found:
  - `geoip2`
  - `pyperclip`
  - `macchanger`
  - `curl`
  - `python3-pip`
  - `geoip-bin`

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/SilenceGeneric/WhereIsWaldo.git
   cd WhereIsWaldo
   ```

2. **Run the program**:

   The program should automatically install any missing dependencies when it is executed. Simply run the following:

   ```bash
   python3 whereiswaldo.py
   ```

   Make sure you are running on a supported system (Debian or Ubuntu) and have internet access for dependency installation.

## Usage

1. Open the program's GUI.
2. Enter the IP address you wish to track in the "Track IP" field.
3. Click the "Track IP" button to start tracking the IP address. The program will display details such as city, country, ISP, ASN, and coordinates.
4. To randomize your MAC address, select a network interface from the dropdown and click "Randomize MAC."
5. You can also copy the tracking information to your clipboard using the "Copy to Clipboard" button.

## Functions Overview

- `install_dependencies()`: Installs the necessary dependencies for the program.
- `download_geoip_db()`: Downloads and extracts the GeoLite2 City database for IP geolocation.
- `check_macchanger_installed()`: Ensures `macchanger` is installed.
- `randomize_mac_address(interface)`: Randomizes the MAC address of the selected network interface.
- `get_ip_details(ip)`: Retrieves detailed information about the IP, including ISP, ASN, city, country, and geographical coordinates.
- `track_ip(ip)`: Handles the IP tracking process and displays the results.


## Troubleshooting

- **Network Connectivity**: Ensure you have an active internet connection before running the program. It requires an internet connection to download dependencies and fetch geolocation data.
- **MAC Address Randomization**: If you encounter issues with MAC address randomization, ensure that `macchanger` is installed and your network interface supports it.

## Contributing

Contributions are welcome! Feel free to fork the repository, submit issues, or open pull requests to help improve the project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
