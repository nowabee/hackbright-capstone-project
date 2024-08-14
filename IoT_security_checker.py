import os
import requests
import scapy.all as scapy
from manuf import manuf
import nmap
import socket
import re
from ipaddress import ip_network, ip_address

# List of known manufacturers with specific categorizations
manufacturer_categories = {
    "sagemcom": "Router",
    "intel": "PC/Laptop",
    "amazontechno": "IoT Device",
    "tuyasmart": "IoT Device",
    "ecobee": "IoT Device",
    "samsungelect": "IoT Device",
    "huizhougaosh": "IoT Device",
    "espressif": "IoT Device",
    "partllresear": "IoT Device"
}

# Threat database with information about common vulnerabilities
threat_database = {
    21: "FTP - Unencrypted file transfer, vulnerable to interception",
    22: "SSH - Secure remote access, ensure strong passwords and disable root login",
    23: "Telnet - Unencrypted communication, vulnerable to interception",
    80: "HTTP - Unencrypted web traffic, vulnerable to interception, use HTTPS instead",
    443: "HTTPS - Secure web traffic, ensure up-to-date SSL certificates",
    445: "SMB - Vulnerable to various attacks, ensure patching and restrict access",
    3389: "RDP - Remote Desktop Protocol, ensure strong passwords and enable Network Level Authentication",
    8000: "Commonly used for development, ensure it is not exposed to the internet",
    8080: "HTTP Alternative - Same vulnerabilities as HTTP, use HTTPS if possible",
}

def download_manuf(url, save_path):
    """
    Download the manuf file from the given URL and save it to the specified path.
    If the file already exists, it will be overwritten.
    """
    response = requests.get(url)
    if response.status_code == 200:
        with open(save_path, 'wb') as file:
            file.write(response.content)
    else:
        print(f"Failed to download manuf file. Status code: {response.status_code}")

def scan(ip):
    print("\nScanning for devices on the network...")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    results = []

    for element in answered_list:
        result = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        results.append(result)
    
    return results

def normalize_string(s):
    """
    Normalize a string by converting to lowercase and removing extra spaces.
    """
    return s.strip().lower() if s else ""

def match_manufacturer(manufacturer):
    """
    Match the manufacturer name to the closest known manufacturer.
    """
    normalized_manufacturer = normalize_string(manufacturer)
    for key in manufacturer_categories.keys():
        if key in normalized_manufacturer:
            return key
    return "unknown"

def categorize_device(manufacturer):
    """
    Categorize the device based on the manufacturer.
    """
    if manufacturer == "Unknown":
        return "Unknown"
    matched_manufacturer = match_manufacturer(manufacturer)
    return manufacturer_categories.get(matched_manufacturer, "IoT Device")

def scan_ports(ip):
    """
    Scan for open ports on the given IP address.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-T4')
        return nm[ip]['tcp'].keys()
    except Exception as e:
        print(f"Error scanning {ip}: {e}")
        return []

def check_security(ip):
    """
    Perform basic security checks on the device.
    """
    open_ports = scan_ports(ip)
    if open_ports:
        return f"Ports Open: {', '.join(map(str, open_ports))}"
    return "No open ports"

def ensure_encryption(ip):
    """
    Check if the device is using encrypted protocols.
    """
    encryption_protocols = {
        'https': 'https://',
        'ssh': 'ssh://',
        'ftps': 'ftps://',
        'imaps': 'imaps://',
        'smtps': 'smtps://'
    }
    encrypted_services = []

    for protocol, url_prefix in encryption_protocols.items():
        try:
            response = requests.head(f"{url_prefix}{ip}", timeout=5, allow_redirects=True)
            if response.status_code in [200, 301, 302, 401, 403]:
                encrypted_services.append(protocol.upper())
        except requests.RequestException:
            continue
    
    if encrypted_services:
        return f"Encrypted Protocols Used: {', '.join(encrypted_services)}"
    else:
        return "No Encrypted Protocols Detected"

def check_default_credentials(ip):
    """
    Check if the device is using default credentials.
    """
    # Simple example, check common default login pages
    common_urls = [
        f"http://{ip}/admin",
        f"http://{ip}/login",
        f"http://{ip}/admin/login"
    ]
    
    for url in common_urls:
        try:
            response = requests.get(url, timeout=5)
            if "login" in response.text.lower():
                return "Default Login Page Detected"
        except requests.RequestException:
            continue
    
    return "No Default Login Page Detected"

def display_device_list(results, manuf_parser):
    print("\nList of Identified Devices on the Network")
    print("No.\tIP Address\t\tMAC Address\t\tManufacturer\t\tCategory")
    print("-------------------------------------------------------------------------------------------------------------------------")
    for index, result in enumerate(results, start=1):
        manufacturer = manuf_parser.get_manuf(result["mac"]) or "Unknown"
        category = categorize_device(manufacturer)
        print(f"{index}\t{result['ip']}\t\t{result['mac']}\t\t{manufacturer}\t\t{category}")

def display_device_details(results, manuf_parser):
    print("\nScanning for Open Ports")
    print("Device : [Manufacturer : Last 6 digits of MAC address]")
    print("-------------------------------------------------------------------------------------------------------------------------")
    for result in results:
        ip = result['ip']
        mac = result['mac']
        manufacturer = manuf_parser.get_manuf(mac) or "Unknown"
        last_6_mac = mac[-6:].upper()
        print(f"Device : [{manufacturer} : {last_6_mac}]")
        
        security_status = check_security(ip)
        encryption_status = ensure_encryption(ip)
        default_credentials = check_default_credentials(ip)
        
        print("Open ports       | Port security  | Encryption   | Default Credential")
        print("-------------------------------------------------------------------------------------------------------------------------")
        print(f"{security_status:<17} | {encryption_status:<15} | {default_credentials}")

def select_device(results):
    """
    Prompt the user to select a device and return the selected device details.
    """
    while True:
        selection = input("\nEnter the number of the device to perform detailed security checks (or 'q' to quit): ").strip()
        if selection.lower() == 'q':
            return None
        try:
            selection = int(selection)
            if 1 <= selection <= len(results):
                return results[selection - 1]
            else:
                print("Invalid selection. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def get_threat_details(port):
    """
    Get threat details from the threat database based on the port number.
    """
    return threat_database.get(port, "No specific threats identified for this port.")

def perform_security_checks(device, manuf_parser):
    """
    Perform and display security checks for the selected device.
    """
    ip = device['ip']
    mac = device['mac']
    manufacturer = manuf_parser.get_manuf(mac) or "Unknown"
    last_6_mac = mac[-6:].upper()

    print(f"\nPerforming Security Scans on Device [{manufacturer} : {last_6_mac}]")
    
    security_status = check_security(ip)
    encryption_status = ensure_encryption(ip)
    default_credentials = check_default_credentials(ip)
    
    print("\nSecurity Check Results:")
    print("Open Ports:       ")
    open_ports = security_status.split(": ")[1] if "Ports Open:" in security_status else ""
    print(f"{security_status}")

    print("\nPort Security:    ")
    if "Ports Open:" in security_status:
        print("Open ports can be exploited by attackers. Consider closing unused ports.")
        for port in open_ports.split(", "):
            port = int(port)
            threat_detail = get_threat_details(port)
            print(f"Port {port}: {threat_detail}")
    else:
        print("No open ports detected. The device is secure from open port vulnerabilities.")
    
    print("\nCommunication Encryption: ")
    if "Encrypted Protocols Used" in encryption_status:
        print(f"The device uses the following secure protocols: {encryption_status.split(': ')[1]}")
    else:
        print("The device does not use secure communication protocols. Consider enabling HTTPS, FTPS, or SSH.")
    
    print("\nDefault Credentials: ")
    if "Default Login Page Detected" in default_credentials:
        print("The device's default login page was detected. Change the default credentials to enhance security.")
    else:
        print("No default login page detected. The device is less likely to be vulnerable to credential-based attacks.")
    
    # Security Summary and Recommendations
    print("\nSecurity Summary:")
    vulnerabilities = []
    if "Ports Open:" in security_status:
        vulnerabilities.append(f"- Open Ports: {security_status}")
    if "No Encrypted Protocols Detected" in encryption_status:
        vulnerabilities.append("- Encryption is not enabled. Consider using HTTPS.")
    if "Default Login Page Detected" in default_credentials:
        vulnerabilities.append("- Default credentials detected. Change the default credentials.")

    if not vulnerabilities:
        print("This device appears to be secure for use.")
    else:
        print("This device has some vulnerabilities that need to be addressed.")
        for recommendation in vulnerabilities:
            print(recommendation)

    print("\nGeneral Security Assessment Conclusion:")
    if not vulnerabilities:
        print("The device is considered safe to use on the network.")
    else:
        print("The device is considered unsafe to use on the network until the vulnerabilities are addressed.")
        provide_guidelines()

def provide_guidelines():
    """
    Provide guidelines for securing the device if it is considered unsafe.
    """
    print("\nRecommendations to Resolve the Vulnerabilities:")
    
    # Step 1: Network Segmentation
    print("\nStep 1: Network Segmentation")
    print("Separating IoT devices onto their own network can help limit the impact of any potential security breaches.")
    segmentation = input("Are your IoT devices on a separate network? (yes/no): ").strip().lower()
    if segmentation == 'no':
        print("To create a separate network for IoT devices, you can follow these general steps based on your router:")
        print("1. Log in to your router's admin interface.")
        print("2. Look for the 'Network' or 'LAN' settings.")
        print("3. Create a new subnet for IoT devices.")
        print("4. Configure your router to assign this subnet to a separate VLAN.")
        print("5. Connect your IoT devices to this new VLAN.")
    else:
        print("Great! Your IoT devices are already segmented.")

    # Step 2: Change Default Credentials
    print("\nStep 2: Change Default Credentials")
    print("Changing default credentials helps to prevent unauthorized access.")
    default_password = input("Have you set a new password for your IoT device? (yes/no): ").strip().lower()
    if default_password == 'no':
        print("To change the default password for your IoT device:")
        print("1. Access the device's admin interface.")
        print("2. Navigate to the 'Account' or 'Security' settings.")
        print("3. Set a strong, unique password.")
        print("4. Save the changes and ensure you remember the new password.")
    else:
        print("Excellent! You have set a new password.")

    # Step 3: Device Firmware Updates
    print("\nStep 3: Device Firmware Updates")
    print("Keeping device firmware up-to-date ensures that security vulnerabilities are patched.")
    firmware_update = input("Do you regularly check for firmware updates for your IoT device? (yes/no): ").strip().lower()
    if firmware_update == 'no':
        print("To check for firmware updates:")
        print("1. Visit the manufacturer's website or access the device's admin interface.")
        print("2. Look for the 'Firmware' or 'Software Update' section.")
        print("3. Follow the instructions to download and apply the latest firmware updates.")
        print("4. Ensure that the device is restarted if required.")
    else:
        print("Good job! Regular updates are important for device security.")

def get_local_ip():
    """
    Get the local IP address of the user.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(('10.254.254.254', 1))  # Doesn't actually connect, just gets the local IP
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error getting local IP address: {e}")
        return None

def main():
    print("\n-------IoT Security Checker-----------------------")
    print("Welcome to the IoT Security Checker script.")
    print("This script helps you scan your network for IoT devices and perform basic security checks on them.")
    print("Developed by: Noah Boahen")

    manuf_url = "https://www.wireshark.org/download/automated/data/manuf"
    manuf_file_path = "manuf"

    # Download the manuf file
    download_manuf(manuf_url, manuf_file_path)

    # Initialize manuf parser with the downloaded manuf file
    manuf_parser = manuf.MacParser(manuf_file_path)
    
    local_ip = get_local_ip()
    if local_ip is None:
        print("Unable to determine local IP address. Exiting.")
        return
    
    # Determine the network range (assuming /24 subnet)
    network = ip_network(f"{local_ip}/24", strict=False)
    network_range = str(network)
    
    while True:
        print(f"\nScanning network range: {network_range}")
        scan_results = scan(network_range)
        display_device_list(scan_results, manuf_parser)

        while True:
            selected_device = select_device(scan_results)
            if selected_device is None:
                print("Exiting the application.")
                return

            perform_security_checks(selected_device, manuf_parser)

            next_action = input("\nTo begin a new network scan, press 'n' and enter. To perform a security scan on another device, enter device no. and press enter. To quit the program, press 'q' and press enter: ").strip().lower()
            if next_action == 'n':
                break
            elif next_action == 'q':
                print("Exiting the application.")
                return
            else:
                try:
                    next_device_index = int(next_action)
                    if 1 <= next_device_index <= len(scan_results):
                        perform_security_checks(scan_results[next_device_index - 1], manuf_parser)
                    else:
                        print("Invalid device number. Please try again.")
                except ValueError:
                    print("Invalid input. Please try again.")

if __name__ == "__main__":
    main()
