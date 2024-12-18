# Async IP and Port Scanner

A Python script that scans randomly generated IPv4 addresses for open HTTP/HTTPS services. It uses weighted port probabilities, asynchronous operations for scalability, and SQLite for storing scan results.

## Features

- Asynchronous scanning with `aiohttp` for high performance.
- Weighted random port selection based on nmap-services data.
- Detects open directory listings using predefined indicators and regex patterns.
- Stores results in an SQLite database.
- Excludes private, multicast, and other non-routable IP ranges.
- Supports verbose output for debugging or monitoring.

## Requirements

- Python 3.8+
- `aiohttp` library

Install dependencies:

```bash
pip install aiohttp
```

## Setup

1.  Clone the repository:
    
    bash
    
    Copy code
    
    `git clone https://github.com/yourusername/async-ip-port-scanner.git cd async-ip-port-scanner`
    
2.  Set up a virtual environment and activate it:
    
    bash
    
    Copy code
    
    `` python -m venv venv source venv/bin/activate  # On Windows, use `venv\Scripts\activate` ``
    
3.  Install dependencies:
    
    bash
    
    Copy code
    
    `pip install -r requirements.txt`
    
4.  Place the `nmap-services` file at `/usr/share/nmap/nmap-services`. Modify `file_path` in the script if the file is located elsewhere.
    
5.  Initialize the SQLite database:
    
    bash
    
    Copy code
    
    `python -m async_scanner.py --setup-db`
    

## Usage

Run the script with:

bash

Copy code

`python async_scanner.py`

### Options

-   `-v`, `--verbose`: Enable verbose output for debugging.

Example:

bash

Copy code

`python async_scanner.py -v`

## Configuration

### IP and Port Ranges

-   IPs are randomly generated, excluding private and reserved ranges.
-   Ports are selected based on weighted probabilities from the `nmap-services` file.

### Open Directory Indicators

Customize the open directory detection logic by editing the `OPEN_DIRECTORY_INDICATORS` or `OPEN_DIRECTORY_INDICATORS_REGEX` lists in the script.

### Database Configuration

Results are stored in an SQLite database named `scan_results.db`. The database schema is automatically created by the script.

## Output

-   Results are stored in the `scan_results.db` SQLite file.
-   Each record includes IP, port, protocol, status code, redirect URL, and open directory detection status.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Feel free to submit issues or pull requests to improve the script!

## Disclaimer

This script is for educational and research purposes only. Ensure you have permission to scan any IP addresses before use.

vbnet

Copy code

``Replace `yourusername` with your GitHub username in the repository URL. Let me know if you need further adjustments!``

4o

