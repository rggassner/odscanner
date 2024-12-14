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

DB_NAME = "scan_results.db"
TABLE_NAME = "scan_results"

OPEN_DIRECTORY_INDICATORS = [
    "Index of /",
    "Directory listing of http",
    "AList",
    "Choose the calibre library to browse",
    "<div class='graph2'>FOLDER</div>",
]

OPEN_DIRECTORY_INDICATORS_REGEX = [
    re.compile(r"<title>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*-\s*/</title>", re.IGNORECASE),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/117.0",
]

EXCLUDED_NETWORKS = [
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("127.0.0.0/8"),
    IPv4Network("0.0.0.0/8"),
    IPv4Network("224.0.0.0/4"),
    IPv4Network("240.0.0.0/4"),
    IPv4Network("100.64.0.0/10"),
    IPv4Network("169.254.0.0/16"),
]

debug_ips=[
        '127.0.0.1',
        ]
debug_ips=False

path_chance = 0.05

POSSIBLE_PATHS = [
    "Data/",
    "media/",
    "foo/",
    "platinum/",
    "PLATINUMTEAM/",
    "pub/",
    ]

PROTOCOL_PORTS = {
    "http": [80, 81, 5244, 8080, 8081, 8089, 8888, 9000, 9092, 28903, 36657],
    "https": [443, 8080],
}

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
            ftp_files TEXT,
            last_scanned TEXT,
            retired BOOLEAN,
            UNIQUE(ip, port, protocol, path)
        )
    """)
    conn.commit()
    conn.close()

async def check_http(ip, port, protocol, verbose=False):
    """
    Scan an HTTP or HTTPS service, optionally including a random path.
    """
    path = random.choice(POSSIBLE_PATHS) if random.random() < path_chance else ""
    url = f"{protocol}://{ip}:{port}/{path}"
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
                return http_code, redirect_url, is_open_directory, content, None, False, path
    except Exception as e:
        if verbose:
            print(f"Error scanning {url} - {e}")
    return None, None, False, None, None, True, path

async def check_port(ip, port, protocol, verbose=False):
    """
    Scan a port using the selected protocol.
    """
    if verbose:
        print(f"Scanning IP {ip} on port {port} ({protocol})...")
    if protocol in ["http", "https"]:
        return await check_http(ip, port, protocol, verbose)
    elif protocol == "ftp":
        return await check_ftp(ip, port, verbose)
    else:
        if verbose:
            print(f"Protocol {protocol} not supported.")
        return None, None, False, None, None, True, ""

def save_to_database(ip, port, protocol, status_code, redirect_url, is_open_directory, content, ftp_files, retired, path, verbose=False):
    """
    Save or update scan result for a single IP and port.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    last_scanned = datetime.utcnow().isoformat()
    cursor.execute(f"""
        SELECT id FROM {TABLE_NAME} WHERE ip = ? AND port = ? AND protocol = ? AND path = ?
    """, (ip, port, protocol, path))
    existing_entry = cursor.fetchone()
    if existing_entry:
        cursor.execute(f"""
            UPDATE {TABLE_NAME}
            SET status_code = ?, redirect_url = ?, is_open_directory = ?, webpage_content = ?,
                ftp_files = ?, last_scanned = ?, retired = ?
            WHERE ip = ? AND port = ? AND protocol = ? AND path = ?
        """, (status_code, redirect_url, is_open_directory, content, ftp_files, last_scanned, retired, ip, port, protocol, path))
        if verbose:
            print(f"Updated database entry for {ip}:{port} ({protocol}, {path}).")
    else:
        cursor.execute(f"""
            INSERT INTO {TABLE_NAME}
            (ip, port, protocol, path, status_code, redirect_url, is_open_directory, webpage_content, ftp_files, last_scanned, retired)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, port, protocol, path, status_code, redirect_url, is_open_directory, content, ftp_files, last_scanned, retired))
        if verbose:
            print(f"Inserted new database entry for {ip}:{port} ({protocol}, {path}).")
    conn.commit()
    conn.close()

async def scan_ips(ip_list, concurrency=4, verbose=False):
    """
    Scan a randomized list of IPs for a randomly selected protocol and port.
    """
    sem = asyncio.Semaphore(concurrency)
    async def bound_check(ip):
        protocol = random.choice(list(PROTOCOL_PORTS.keys()))  # Choose a protocol at random
        port = random.choice(PROTOCOL_PORTS[protocol])  # Choose a port for the protocol
        async with sem:
            result = await check_port(ip, port, protocol, verbose)
            save_to_database(ip, port, protocol, *result, verbose=verbose)  # Save result after each scan
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
    ip_count = 512000  # Number of IPs to scan in each run
    concurrency = 5
    ip_list = generate_random_ips(ip_count)
    asyncio.run(scan_ips(ip_list, concurrency, args.verbose))
    print("Scan completed.")
