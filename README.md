# **WhereIsWaldo: 
Network Information and Geolocation Script**

WhereIsWaldo is a Python script that provides detailed network information from your system's active network connections. It collects live IP addresses, resolves hostnames, performs traceroutes, and fetches geolocation data, all without requiring external API keys or licenses.

## **Features**

- **Live IP Detection**: Detects active network connections and retrieves the IP addresses.
- **Hostname Resolution**: Resolves hostnames from detected live IPs.
- **Traceroute**: Performs traceroute to show the network path to each live IP address.
- **Geolocation**: Fetches detailed geolocation information (such as country, city, latitude, and longitude) for each IP address.
- **Self-contained**: The script runs entirely locally with no need for external APIs or licenses.

## **Requirements**

Before running WhereIsWaldo, ensure that your system meets the following dependencies. The script will automatically handle installing necessary Python libraries.

### **Python Dependencies**
- Python 3.6 or newer
- `psutil` (for retrieving network connection data)
- `socket` (for hostname resolution)
- `subprocess` (for running system commands like `traceroute`)
- `ipwhois` (for IP geolocation)

The script will automatically create a virtual environment (`venv`) and install any missing dependencies.

### **Linux Dependencies**
- `traceroute` (used to analyze the network path to each live IP)

## **Installation and Usage**

### **Step 1: Clone the Repository**

Clone the WhereIsWaldo repository to your local machine:

```bash
git clone https://github.com/SilenceGeneric/WhereIsWaldo.git
cd WhereIsWaldo
```

### **Step 2: Install Dependencies**

The script will automatically create a virtual environment and install the required Python packages. No manual installation is necessary.

### **Step 3: Run the Script**

Run the script with Python 3:

```bash
python3 whereiswaldo.py
```

### **Output**

The script will output the following information:

- **Live IP Addresses**: The active IP addresses detected in your system's network connections.
- **Hostnames**: Resolved hostnames for each live IP.
- **Traceroute**: The network path from your system to each live IP address.
- **Geolocation**: Country, region, city, and latitude/longitude information for each live IP.

Example output:
```
2025-03-10 12:34:56,789 - INFO - Live IP addresses found: ['192.168.1.10', '10.0.0.5']
2025-03-10 12:34:56,789 - INFO - IP: 192.168.1.10 | Hostname: my-router.local
2025-03-10 12:34:56,789 - INFO - IP: 10.0.0.5 | Hostname: server.local
2025-03-10 12:34:56,789 - INFO - Traceroute result for 192.168.1.10:
2025-03-10 12:34:56,789 - INFO - traceroute to 192.168.1.10 (192.168.1.10), 30 hops max
...
```

## **License**

WhereIsWaldo is open-source software released under the [MIT License](LICENSE).

---
