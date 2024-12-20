#!venv/bin/python
import sqlite3
import random
import aiohttp
import asyncio,argparse
from datetime import datetime
from multiprocessing import Pool, Manager
import ssl,re
from datetime import datetime, timezone


DB_NAME = "scan_results.db"
TABLE_NAME = "scan_results"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/117.0",
]

OPEN_DIRECTORY_INDICATORS = [
    "Parent Directory",
    "folder listing",
    "Browsing",
    "<h1>Index of",
    "folder view",
    "Directory Contents",
    "Index of /",
    "Directory listing of http",
    "AList",
    "Choose the calibre library to browse",
    "<div class='graph2'>FOLDER</div>",
]

OPEN_DIRECTORY_INDICATORS_REGEX = [
    re.compile(r"<title>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*-\s*/</title>", re.IGNORECASE),
    re.compile(r"<title>Index of .*?</title>", re.IGNORECASE),
    re.compile(r"<h1>Index of .*?</h1>", re.IGNORECASE),
    re.compile(r"Directory listing for .*", re.IGNORECASE),
]


async def check_http(ip, port, protocol, path, verbose=False):
    if verbose:
        print(f"Scanning {protocol}://{ip}:{port}/{path}...")
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
                return http_code, redirect_url, is_open_directory, content, None, False
    except Exception as e:
        if verbose:
            print(f"Error scanning {url} - {e}")
    return None, None, False, None, None, True


def load_paths(file_path):
    with open(file_path, 'r') as f:
        paths = f.readlines()
    weights = [(len(paths) - i) ** 8 for i in range(len(paths))]
    return paths, weights

def select_path_with_weight(paths, weights):
    chosen_path = random.choices(paths, weights=weights, k=1)[0]
    return chosen_path.strip() 

def save_to_database(ip, port, protocol, path, status_code, redirect_url, is_open_directory, content, retired, verbose=False):
    """
    Save or update scan result for a single IP and port.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    last_scanned = datetime.now(timezone.utc).isoformat()
    cursor.execute(f"""
        SELECT id FROM {TABLE_NAME} WHERE ip = ? AND port = ? AND protocol = ? AND path = ?
    """, (ip, port, protocol, path))
    existing_entry = cursor.fetchone()
    if existing_entry:
        cursor.execute(f"""
            UPDATE {TABLE_NAME}
            SET status_code = ?, redirect_url = ?, is_open_directory = ?, webpage_content = ?,
                last_scanned = ?, retired = ?
            WHERE ip = ? AND port = ? AND protocol = ? AND path = ? 
        """, (status_code, redirect_url, is_open_directory, content, last_scanned, retired, ip, port, protocol, path))
        if verbose:
            print(f"Updated database entry for {protocol}://{ip}:{port}/{path}.")
    else:
        cursor.execute(f"""
            INSERT INTO {TABLE_NAME}
            (ip, port, protocol, path, status_code, redirect_url, is_open_directory, webpage_content, last_scanned, retired)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, port, protocol, path, status_code, redirect_url, is_open_directory, content, last_scanned, retired))
        if verbose:
            print(f"Inserted database entry for {protocol}://{ip}:{port}/{path}.")
    conn.commit()
    conn.close()

def get_random_entry():
    """
    Fetch a random database entry without a path.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(f"""
        SELECT ip, port, protocol FROM {TABLE_NAME} WHERE (path = '' OR path IS NULL) AND retired = 0
        ORDER BY RANDOM() LIMIT 1
    """)
    entry = cursor.fetchone()
    conn.close()
    return entry

def worker(task_count, verbose, paths, weights):
    """
    Worker function for multiprocessing.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for _ in range(task_count):
        entry = get_random_entry()
        if not entry:
            if verbose:
                print("No more entries to process.")
            break
        ip, port, protocol = entry
        path = select_path_with_weight(paths, weights)
        result = loop.run_until_complete(check_http(ip, port, protocol, path, verbose=verbose))
        if result:
            status_code, redirect_url, is_open_directory, content, _, retired = result
            save_to_database(ip, port, protocol, path, status_code, redirect_url, is_open_directory, content, retired, verbose)

if __name__ == "__main__":
    file_path = 'dsstorewordlist.txt' 
    paths, weights = load_paths(file_path)
    parser = argparse.ArgumentParser(description="Run path scanning tasks with multiprocessing.")
    parser.add_argument("--iterations", type=int, default=10, help="Number of iterations to run per process.")
    parser.add_argument("--processes", type=int, default=4, help="Number of processes to run simultaneously.")
    parser.add_argument("--verbose",default=True, action="store_true", help="Enable verbose output.")
    args = parser.parse_args()
    with Pool(args.processes) as pool:
        pool.starmap(worker, [(args.iterations, args.verbose,paths,weights) for _ in range(args.processes)])

