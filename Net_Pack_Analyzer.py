import socket
import struct
import textwrap
import datetime

def print_banner():
    """Display the banner in ASCII art style."""
    banner = """
 _   _ _____ _____ _____ _______        _   _  _____ ______ ______  
| \ | |_   _/ ____|_   _|  __ \ \      | \ | |/ ____|  ____|  ____| 
|  \| | | || (___   | | | |__) \ \     |  \| | (___ | |__  | |__    
| . ` | | | \___ \  | | |  _  / \ \ /\ | . ` |\___ \|  __| |  __|   
| |\  |_| |_ ____) |_| |_| | \ \  \ V  | |\  |____) | |____| |____  
|_| \_|_____|_____/|_____|_|  \_\  \_/  |_| \_|_____/|______|______| 
    """
    print(banner)

def format_multi_line(prefix, string, size=80):
    """Format a string to display multiple lines."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(b) for b in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

class PacketSniffer:
    """Class for capturing and analyzing network packets."""

    def __init__(self, interface):
        """Initialize the sniffer."""
        self.interface = interface

    def analyze_packet(self, packet_data):
        """Analyze a single network packet."""
        try:
            eth_length = 14
            eth_header = packet_data[:eth_length]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])

            print("\n" + "=" * 80)
            print(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Ethernet Protocol: {eth_protocol}")

            if eth_protocol == 8:  
                self.analyze_ipv4_packet(packet_data[eth_length:])
        except Exception as e:
            print(f"Error analyzing packet: {e}")

    def analyze_ipv4_packet(self, packet):
        """Analyze IPv4 packets."""
        ip_header = packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        print(f"IPv4 Packet: Version {version}, Header Length {ihl * 4}")
        print(f"TTL: {ttl}, Protocol: {protocol}, Source: {s_addr}, Destination: {d_addr}")

        if protocol == 6:
            self.analyze_tcp_packet(packet[ihl * 4:])
        elif protocol == 17:  
            self.analyze_udp_packet(packet[ihl * 4:])
        elif protocol == 1:
            self.analyze_icmp_packet(packet[ihl * 4:])

    def analyze_tcp_packet(self, packet):
        """Analyze TCP packets."""
        tcp_header = packet[:20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        data_offset = (tcph[4] >> 4) * 4

        print("TCP Packet:")
        print(f"Source Port: {source_port}, Destination Port: {dest_port}")
        print(f"Sequence Number: {sequence}, Acknowledgement: {acknowledgement}")
        print(f"Data Offset: {data_offset}")

    def analyze_udp_packet(self, packet):
        """Analyze UDP packets."""
        udp_header = packet[:8]
        udph = struct.unpack('!HHHH', udp_header)

        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]

        print("UDP Packet:")
        print(f"Source Port: {source_port}, Destination Port: {dest_port}, Length: {length}")

    def analyze_icmp_packet(self, packet):
        """Analyze ICMP packets."""
        icmp_header = packet[:4]
        icmph = struct.unpack('!BBH', icmp_header)

        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]

        print("ICMP Packet:")
        print(f"Type: {icmp_type}, Code: {code}, Checksum: {checksum}")

    def start_sniffing(self):
        """Start capturing packets."""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sock.bind((self.interface, 0))

            print(f"Sniffer started on interface: {self.interface}")
            while True:
                raw_data, _ = sock.recvfrom(65536)
                self.analyze_packet(raw_data)
        except PermissionError:
            print("Error: You need to run this program as root.")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    print_banner()
    interface = input("Enter the network interface to sniff packets (e.g., eth0, wlan0): ")
    sniffer = PacketSniffer(interface)
    sniffer.start_sniffing()
