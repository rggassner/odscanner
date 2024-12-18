#! venv/bin/python
import sqlite3
from ipaddress import IPv4Network, IPv4Address
from PIL import Image

# Define the excluded networks
EXCLUDED_NETWORKS = [
    IPv4Network("0.0.0.0/8"),
    IPv4Network("10.0.0.0/8"),
    IPv4Network("100.64.0.0/10"),
    IPv4Network("127.0.0.0/8"),
    IPv4Network("169.254.0.0/16"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("224.0.0.0/4"),
    IPv4Network("240.0.0.0/4"),
]

def is_excluded(network_id):
    """Check if a /24 network is in the excluded ranges."""
    # Convert the network ID to an IPv4 address
    network_ip = IPv4Address(network_id << 8)  # Shift by 8 bits for /24
    for excluded in EXCLUDED_NETWORKS:
        if IPv4Network(f"{network_ip}/24").subnet_of(excluded):
            return True
    return False

def ip_to_int(ip):
    """Convert an IPv4 address to a 32-bit integer."""
    octets = ip.split('.')
    return (int(octets[0]) << 24) | (int(octets[1]) << 16) | (int(octets[2]) << 8) | int(octets[3])

def fetch_network_status(cursor):
    """Fetch the retired status of IPs grouped by /24 network."""
    query = """
    SELECT ip, retired
    FROM scan_results;
    """
    cursor.execute(query)
    result = cursor.fetchall()
    
    # Dictionary to track the retired statuses of each /24 network
    network_status = {}
    
    for ip, retired in result:
        ip_int = ip_to_int(ip)  # Convert the IP address to integer
        network_id = ip_int >> 8  # Get the /24 network (shift by 8 bits)
        
        if network_id not in network_status:
            network_status[network_id] = {'green': False, 'red': False}

        if retired == 0:
            network_status[network_id]['green'] = True  # At least one port retired=0
        elif retired == 1:
            network_status[network_id]['red'] = True  # At least one port retired=1
    
    return network_status

def generate_ipv4_network_image(size=4096, db_path="scan_results.db"):
    """Generate an image representing /24 networks in IPv4 space based on database content."""
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Fetch network status from the database
    network_status = fetch_network_status(cursor)

    # Close the database connection
    conn.close()

    # Create the image with a white background
    img = Image.new('RGB', (size, size), "white")
    pixels = img.load()

    for x in range(size):
        for y in range(size):
            # Compute the /24 network ID from coordinates
            network_id = (x << 12) | y

            # Check if the network is excluded
            if is_excluded(network_id):
                pixels[x, y] = (128,128 ,128)  # Black for excluded networks
            else:
                # Check the network status and set the pixel color
                if network_id in network_status:
                    if network_status[network_id]['green']:
                        pixels[x, y] = (0, 255, 0)  # Green for active network with retired=0
                    elif network_status[network_id]['red']:
                        pixels[x, y] = (255, 0, 0)  # Red for network with retired=1
                    else:
                        pixels[x, y] = (255, 255, 255)  # White for network with no entries
                else:
                    pixels[x, y] = (255, 255, 255)  # White for network with no entries

    return img

# Generate the image
size = 4096  # Grid size for /24 networks
ipv4_network_image = generate_ipv4_network_image(size)
ipv4_network_image.save("ipv4_networks_colored.png")
ipv4_network_image.show()

