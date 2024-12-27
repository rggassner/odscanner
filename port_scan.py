#! venv/bin/python
import asyncio
import aiohttp
import random
import sqlite3
from datetime import datetime
import argparse
from ipaddress import IPv4Address, IPv4Network
import ssl
import re
from datetime import datetime, timezone
from shared_content import OPEN_DIRECTORY_INDICATORS, OPEN_DIRECTORY_INDICATORS_REGEX, USER_AGENTS, EXCLUDED_NETWORKS,DB_NAME, TABLE_NAME

file_path = "/usr/share/nmap/nmap-services"

RANDOM_PORT_CHANCE = 0.1

debug_ips=[
        '127.0.0.1',
        ]
debug_ips=False

def setup_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code INTEGER,
            redirect_url TEXT,
            is_open_directory BOOLEAN,
            webpage_content TEXT,
            last_scanned TEXT,
            retired BOOLEAN,
            UNIQUE(ip, port, protocol, path)
        )
    """)
    conn.commit()
    conn.close()

def load_nmap_services(file_path):
    """Load and parse nmap-services file to get port probabilities."""
    ports = {}
    with open(file_path, "r") as file:
        for line in file:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            port_protocol = parts[1]
            probability = float(parts[2])
            port, protocol = port_protocol.split("/")
            if protocol == "tcp":  # We're only interested in TCP ports
                ports[int(port)] = probability
    return ports

def get_http_or_https():
    return random.choices(["http", "https"], weights=[65, 35], k=1)[0]

def generate_random_port(ports, full_range=(1, 65535)):
    """Generate a random port with weighted probabilities."""
    """https://scottbrownconsulting.com/2018/11/nmap-top-ports-frequencies-study/"""
    """LZR: Identifying Unexpected Internet Services"""
    """https://arxiv.org/pdf/2301.04841"""
    # Get all ports and their weights
    known_ports = list(ports.keys())
    known_weights = list(ports.values())

    # Assign very small weights to ports with 0.000000
    min_known_weight = min(w for w in known_weights if w > 0)
    adjusted_weights = [w if w > 0 else min_known_weight / 10 for w in known_weights]

    # Add ports not in the known list with even smaller probabilities
    all_ports = list(range(full_range[0], full_range[1] + 1))
    unknown_ports = set(all_ports) - set(known_ports)
    min_unknown_weight = min(adjusted_weights) / 10
    unknown_weights = [min_unknown_weight] * len(unknown_ports)

    # Combine known and unknown ports
    combined_ports = known_ports + list(unknown_ports)
    combined_weights = adjusted_weights + unknown_weights

    # Normalize weights to sum up to 1
    total_weight = sum(combined_weights)
    normalized_weights = [w / total_weight for w in combined_weights]

    # Select a random port based on probabilities
    return random.choices(combined_ports, weights=normalized_weights, k=1)[0]


async def check_http(ip, port, protocol, verbose=False):
    """
    Scan an HTTP or HTTPS service
    """
    if verbose:
        print(f"Scanning IP {ip} on port {port} ({protocol})...")
    url = f"{protocol}://{ip}:{port}"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(url, timeout=5, ssl=ssl_context, allow_redirects=True) as response:
                content = await response.text()
                http_code = response.status
                is_open_directory = any(indicator in content for indicator in OPEN_DIRECTORY_INDICATORS)
                if not is_open_directory:
                    is_open_directory = any(regex.search(content) for regex in OPEN_DIRECTORY_INDICATORS_REGEX)
                redirect_url = str(response.url) if response.history else None
                return http_code, redirect_url, is_open_directory, content, None, False
    except Exception as e:
        if verbose:
            print(f"Error scanning {url} - {e}")
    return None, None, False, None, None, True

def save_to_database(ip, port, protocol, status_code, redirect_url, is_open_directory, content, retired, verbose=False):
    """
    Save or update scan result for a single IP and port.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    last_scanned = datetime.now(timezone.utc).isoformat()
    cursor.execute(f"""
        SELECT id FROM {TABLE_NAME} WHERE ip = ? AND port = ? AND protocol = ? AND path = ?
    """, (ip, port, protocol, ''))
    existing_entry = cursor.fetchone()
    if existing_entry:
        cursor.execute(f"""
            UPDATE {TABLE_NAME}
            SET status_code = ?, redirect_url = ?, is_open_directory = ?, webpage_content = ?,
                last_scanned = ?, retired = ?
            WHERE ip = ? AND port = ? AND protocol = ? AND path = ? 
        """, (status_code, redirect_url, is_open_directory, content, last_scanned, retired, ip, port, protocol, ''))
        if verbose:
            print(f"Updated database entry for {protocol}://{ip}:{port}.")
    else:
        cursor.execute(f"""
            INSERT INTO {TABLE_NAME}
            (ip, port, protocol, status_code, redirect_url, is_open_directory, webpage_content, last_scanned, retired, path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, port, protocol, status_code, redirect_url, is_open_directory, content, last_scanned, retired, ''))
        if verbose:
            print(f"Inserted database entry for {protocol}://{ip}:{port}.")
    conn.commit()
    conn.close()

async def scan_ips(ip_list, concurrency=4, verbose=False):
    """
    Scan a randomized list of IPs for a randomly selected protocol and port.
    """
    sem = asyncio.Semaphore(concurrency)
    
    async def bound_check(ip):
        protocol = get_http_or_https()  # Choose a protocol at random
        if random.random() < RANDOM_PORT_CHANCE:  
            port = generate_random_port(ports)  # Choose a random non-default port
        else:
            port = 80 if protocol == "http" else 443  # Use default ports for HTTP/HTTPS

        async with sem:
            result = await check_http(ip, port, protocol, verbose)
            if result:
                status_code, redirect_url, is_open_directory, content, _, retired = result
                save_to_database(
                    ip, port, protocol, status_code, redirect_url, is_open_directory, content, retired, verbose=verbose
                )  # Save result after each scan
    tasks = [bound_check(ip) for ip in ip_list]
    await asyncio.gather(*tasks)

def generate_random_ips(count):
    """
    Generate a random list of IPv4 addresses, excluding specific ranges.
    """
    ips = []
    while len(ips) < count:
        ip = IPv4Address(random.randint(0, 2**32 - 1))
        if not any(ip in network for network in EXCLUDED_NETWORKS):
            ips.append(str(ip))
    if debug_ips:
        return debug_ips
    return ips

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan IP addresses for open ports and services.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    setup_database()

    # Load ports and their probabilities
    ports = load_nmap_services(file_path)

    ip_count = 4096  # Number of IPs to scan in each run
    concurrency = 2
    ip_list = generate_random_ips(ip_count)
    asyncio.run(scan_ips(ip_list, concurrency, args.verbose))
    print("Scan completed.")
