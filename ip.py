import pyshark
import socket

def get_local_ip():
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Connect to an external server (doesn't have to be reachable)
        s.connect(("8.8.8.8", 80))

        # Get the local IP address
        local_ip = s.getsockname()[0]

        # Close the socket
        s.close()

        return local_ip
    except Exception as e:
        return str(e)

def is_spoofed_ip(packet, allowed_ip_range):
    try:
        source_ip = packet.ip.src
        # Check if the source IP is not within the allowed IP range
        if source_ip not in allowed_ip_range:
            return True
    except AttributeError:
        # Handle packets that do not contain an IP layer
        return False
    return False

def packet_capture(interface, allowed_ip_range):
    capture = pyshark.LiveCapture(interface=interface)

    try:
        for packet in capture.sniff_continuously():
            if is_spoofed_ip(packet, allowed_ip_range):
                print(f"Spoofed packet detected! Source IP: {packet.ip.src}")
    except KeyboardInterrupt:
        print("Capture stopped.")

def main():
    local_ip = get_local_ip()
    if not local_ip.startswith("127.0.0.1"):
        print(f"Your local IP address is: {local_ip}")
    else:
        print("Unable to determine local IP address. Check your network connection.")

    # Input for the network interface
    network_interface = input("Enter your network interface (e.g., 'eth0', 'en0', 'wlan0'): ")

    # Define the allowed IP address range (change this to your network's IP range)
    allowed_ip_range = ["192.168.1.0", "192.168.1.255"]

    print("Starting capture...")
    try:
        # Start capturing packets while retrieving local IP address
        packet_capture(network_interface, allowed_ip_range)
        print("Capture started.")
    except Exception as e:
        print(f"Capture not started: {e}")

if __name__ == "__main__":
    main()


