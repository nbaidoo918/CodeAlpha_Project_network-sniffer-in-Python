import socket
import struct
import textwrap
import os # Import os to check the operating system

# Constants for formatting output
TAB_1 = "\t - "
TAB_2 = "\t\t - "
TAB_3 = "\t\t\t - "
TAB_4 = "\t\t\t\t - "

DATA_TAB_1 = "\t "
DATA_TAB_2 = "\t\t "
DATA_TAB_3 = "\t\t\t "
DATA_TAB_4 = "\t\t\t\t "

# Unpacks Ethernet Frame
def ethernet_frame(data):
    # We capture the data and unpack the first 14 bytes:
    # 6 bytes for destination MAC, 6 for source MAC, 2 for EtherType.
    # '!' : Network byte order (big-endian)
    # '6s': 6 bytes as a string (MAC addresses)
    # 'H' : 2 bytes as an unsigned short (EtherType)
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    # Convert protocol to host byte order and format MAC addresses
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Returns properly formatted MAC address (e.g., AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    # Convert each byte to a two-digit hexadecimal string
    bytes_addr_str = map('{:02x}'.format, bytes_addr)
    # Join the hex strings with colons and convert to uppercase
    mac_addr = ':'.join(bytes_addr_str).upper()
    return mac_addr

# Unpacks IPv4 Packet Headers
def ipv4_packet(data):
    # First byte contains version (4 bits) and header length (4 bits)
    version_header_length = data[0]
    version = version_header_length >> 4  # Shift right by 4 to get the version
    header_length = (version_header_length & 15) * 4 # Mask with 0xF (15) to get header length in 4-byte words

    # Unpack TTL, Protocol, Source IP, Target IP
    # '!': Network byte order
    # '8x': Skip the first 8 bytes (Version, Header Length, ToS, Total Length, Identification, Flags, Fragment Offset)
    # 'B': Unsigned char (1 byte) for TTL
    # 'B': Unsigned char (1 byte) for Protocol
    # '2x': Skip 2 bytes (Header Checksum)
    # '4s': 4 bytes as string for Source IP
    # '4s': 4 bytes as string for Target IP
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    # Return parsed fields and the rest of the data (payload)
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Returns properly formatted IPv4 address
def ipv4(addr):
    # Convert each byte of the address to a string and join with dots
    return '.'.join(map(str, addr))

# Unpacks ICMP packet
def icmp_packet(data):
    # Unpack ICMP Type, Code, and Checksum
    # '!': Network byte order
    # 'B': Unsigned char (1 byte) for Type
    # 'B': Unsigned char (1 byte) for Code
    # 'H': Unsigned short (2 bytes) for Checksum
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    # Return parsed fields and the rest of the data
    return icmp_type, code, checksum, data[4:]

# Unpacks TCP segment
def tcp_segment(data):
    # Unpack Source Port, Destination Port, Sequence Number, Acknowledgement Number, and Offset/Reserved/Flags
    # '!': Network byte order
    # 'H': Unsigned short (2 bytes) for Ports
    # 'L': Unsigned long (4 bytes) for Sequence and Acknowledgement numbers
    # 'H': Unsigned short (2 bytes) for Offset, Reserved, and Flags field
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])

    # Calculate header length (offset)
    # The offset is in the first 4 bits of offset_reserved_flags, representing 4-byte words
    offset = (offset_reserved_flags >> 12) * 4
    
    # Extract individual flags by masking and shifting
    flag_urg = (offset_reserved_flags & 32) >> 5 # Urgent Pointer
    flag_ack = (offset_reserved_flags & 16) >> 4 # Acknowledgement
    flag_psh = (offset_reserved_flags & 8) >> 3  # Push
    flag_rst = (offset_reserved_flags & 4) >> 2  # Reset
    flag_syn = (offset_reserved_flags & 2) >> 1  # Synchronize
    flag_fin = offset_reserved_flags & 1         # Finish

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpacks UDP segment
def udp_packet(data):
    # Unpack Source Port, Destination Port, and Length
    # '!': Network byte order
    # 'H': Unsigned short (2 bytes) for Ports and Length
    # '2x': Skip 2 bytes (Checksum, which is optional in UDP for IPv4)
    # Note: The actual UDP header is 8 bytes. struct.unpack needs to account for the full slice.
    src_port, dest_port, length = struct.unpack('! H H H', data[:6]) # Read first 6 bytes for ports and length
    # The UDP checksum is at data[6:8]
    # The actual payload starts after 8 bytes.
    return src_port, dest_port, length, data[8:]


# Formats multi-line data (hex and ASCII representation)
def format_multi_line(prefix, string_data, size=20):
    if isinstance(string_data, bytes):
        lines = []
        for i in range(0, len(string_data), size):
            chunk = string_data[i:i + size]
            hex_part = ' '.join(f'{byte:02x}' for byte in chunk)
            # Replace non-printable characters with '.' for the text part
            text_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
            lines.append(f"{prefix} {hex_part.ljust(size * 3)}  {text_part}")
        return '\n'.join(lines)
    elif isinstance(string_data, str): # Handle if it's already a string (e.g. error message)
        return prefix + string_data
    return prefix + "Data format not recognized for multi-line display."


# Main function to capture and process packets
def main():
    conn = None # Initialize conn
    host = "" # Initialize host

    # Platform-specific socket setup
    if os.name == 'nt':  # Check if the OS is Windows ('nt')
        try:
            host = socket.gethostbyname(socket.gethostname())
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            conn.bind((host, 0)) # Bind to the host IP and any available port
            # Include IP headers in the captured packets
            conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Enable promiscuous mode to receive all packets
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            print(f"[*] Sniffing on host: {host} (Windows Mode - IP Packets Only)")
            print("[!] Ensure this script is run with Administrator privileges on Windows.")
        except socket.error as e:
            print(f"Socket error on Windows: {e}")
            print("Make sure you are running this script as an Administrator.")
            return # Exit if socket setup fails
    else:  # For Linux/Unix-like systems
        try:
            # For Linux, AF_PACKET allows capturing raw link-layer frames
            # socket.ntohs(3) captures all protocols (ETH_P_ALL)
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            print("[*] Sniffing on all interfaces (Linux/Unix Mode - Ethernet Frames)")
            print("[!] Ensure this script is run with root privileges on Linux/Unix if needed.")
        except socket.error as e:
            print(f"Socket error on Linux/Unix: {e}")
            print("Make sure you have necessary permissions (e.g., run as root or with CAP_NET_RAW).")
            return # Exit if socket setup fails
        except AttributeError:
            print("AF_PACKET not available on this system. This mode is for Linux/Unix.")
            return


    try:
        while True:
            raw_data, addr = conn.recvfrom(65536) # Receive packet data

            eth_proto = 0 # Initialize eth_proto for the conditional check later

            if os.name == 'nt':
                # For Windows (AF_INET, SOCK_RAW), raw_data starts with the IP header.
                # We skip the ethernet_frame part.
                (version, header_length, ttl, proto_from_ip, src_ip, target_ip, ip_payload_data) = ipv4_packet(raw_data)
                print("\nIPv4 Packet (No Ethernet Frame Data on Windows via this method):")
                print(TAB_1 + f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
                print(TAB_1 + f'Protocol: {proto_from_ip}, Source: {src_ip}, Target: {target_ip}')
                
                data_for_transport_layer = ip_payload_data 
                current_proto_for_logic = proto_from_ip # This is IP's protocol field (e.g., 1 for ICMP, 6 for TCP, 17 for UDP)
            
            else: # Linux/Unix path (AF_PACKET)
                dest_mac, src_mac, eth_proto_val, data_after_ethernet = ethernet_frame(raw_data)
                eth_proto = eth_proto_val # Assign to eth_proto for the later check
                print("\nEthernet Frame:")
                print(TAB_1 + f"Destination MAC Address: {dest_mac}, Source MAC Address: {src_mac}, Protocol: {eth_proto}")
                
                data_for_transport_layer = data_after_ethernet
                current_proto_for_logic = eth_proto # This is Ethernet's EtherType (e.g., 0x0800 (2048) for IPv4)

                # If it's an IPv4 packet (EtherType 0x0800, which is 2048 in decimal, or 8 if htons was not used on 0x0800)
                # Note: socket.htons(ETH_P_IPV4) where ETH_P_IPV4 is 0x0800 would result in 8.
                # Your ethernet_frame function uses socket.htons(proto), so if proto was 0x0800, it becomes 8.
                if eth_proto == 8: # Check for IPv4 EtherType (which is 8 after htons(0x0800))
                    (version, header_length, ttl, proto_from_ip, src_ip, target_ip, ip_payload_data) = ipv4_packet(data_after_ethernet)
                    print(TAB_1 + 'IPv4 Packet:')
                    print(TAB_2 + f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
                    print(TAB_2 + f'Protocol: {proto_from_ip}, Source: {src_ip}, Target: {target_ip}')
                    data_for_transport_layer = ip_payload_data
                    current_proto_for_logic = proto_from_ip # Update to IP's protocol for TCP/UDP/ICMP check
                else:
                    print(TAB_1 + f'Non-IPv4 Data (EtherType: {eth_proto}):')
                    print(format_multi_line(DATA_TAB_2, data_for_transport_layer))
                    continue # Skip further IP-based processing for non-IPv4 frames

            # Now, current_proto_for_logic holds the IP protocol number (1, 6, 17, etc.)

            # Check ICMP (Protocol number 1)
            if current_proto_for_logic == 1:
                icmp_type, code, checksum, icmp_data = icmp_packet(data_for_transport_layer)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, icmp_data))

            # Check TCP (Protocol number 6)
            elif current_proto_for_logic == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, tcp_data = tcp_segment(data_for_transport_layer)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(TAB_2 + f'Sequence: {sequence}, Acknowledgement: {acknowledgement}')
                print(TAB_2 + "Flags:")
                print(TAB_3 + f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, tcp_data))

            # Check UDP (Protocol number 17)
            elif current_proto_for_logic == 17:
                src_port, dest_port, length, udp_data = udp_packet(data_for_transport_layer)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, udp_data))

            # Else, if it was an IP packet but not ICMP, TCP, or UDP
            # This condition ensures we only try to print "Other IP Protocol Data" if we actually processed an IP packet.
            elif (os.name == 'nt') or (os.name != 'nt' and eth_proto == 8):
                print(TAB_1 + f'Other IP Protocol Data (Protocol Number: {current_proto_for_logic}):')
                print(format_multi_line(DATA_TAB_2, data_for_transport_layer))

    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
    except socket.error as e:
        print(f"\nRuntime socket error: {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
    finally:
        if os.name == 'nt' and conn:
            try:
                conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF) # Turn off promiscuous mode on Windows
                conn.close()
            except socket.error as e:
                print(f"Error closing Windows socket: {e}")
        elif conn: # For Linux or other OS if conn was initialized
            try:
                conn.close()
            except socket.error as e:
                print(f"Error closing socket: {e}")
        print("Connection closed.")

if __name__ == '__main__':
    main()
