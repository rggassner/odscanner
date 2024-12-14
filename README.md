
Open Directory & Port Scanner
Welcome to the Open Directory & Port Scanner project! This Python-based tool is designed to scan IP addresses for open ports and services, specifically detecting open directories on web servers. Built for scalability and efficiency, it leverages asynchronous programming with aiohttp and supports saving results to an SQLite database.

Features
Open Directory Detection:
Detects open directories using predefined strings and regex patterns, including IP-based patterns in HTML titles.
Protocol Support:
HTTP, HTTPS, and FTP scanning.
Randomized Paths:
Optionally appends random paths to requests for broader scanning.
Excluded Networks:
Automatically excludes private and reserved IP ranges.
SQLite Integration:
Saves scan results into an SQLite database for easy querying and reporting.
Concurrency:
Asynchronous scanning supports high concurrency for faster results.
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/rggassner/odscanner.git
cd open-directory-scanner
Set up a virtual environment:

bash
Copy code
python3 -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
Install dependencies:

bash
Copy code
pip install -r requirements.txt
Set up the database:

bash
Copy code
python main.py --setup-database
Usage
Run the scanner using the following command:

bash
Copy code
python main.py
Options
-v or --verbose: Enable detailed output during the scan.
Example with verbose mode:

bash
Copy code
python main.py -v
How It Works
IP Generation:

Generates a randomized list of public IPv4 addresses, excluding private and reserved ranges.
Randomized Scanning:

Randomly selects a protocol (HTTP/HTTPS) and port from predefined lists.
Optional random paths can be appended to URLs to increase detection chances.
Open Directory Detection:

Uses both exact string matches and regex patterns to detect open directories.
Database Storage:

Saves scan results (IP, port, protocol, response status, directory detection, etc.) in an SQLite database.
Configuration
Random Paths
Modify the POSSIBLE_PATHS list in main.py to add or customize paths:

python
Copy code
POSSIBLE_PATHS = [
    "Data/",
    "media/",
    "buitenwesten/",
    "foo/",
    "platinum/",
]
Protocols and Ports
Add or remove protocols and their respective ports in the PROTOCOL_PORTS dictionary:

python
Copy code
PROTOCOL_PORTS = {
    "http": [80, 8080, 8888],
    "https": [443, 8443],
}
Open Directory Indicators
Edit the OPEN_DIRECTORY_INDICATORS and OPEN_DIRECTORY_INDICATORS_REGEX lists to include additional patterns:

python
Copy code
OPEN_DIRECTORY_INDICATORS = [
    "Index of /",
    "AList",
]
OPEN_DIRECTORY_INDICATORS_REGEX = [
    re.compile(r"<title>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*-\s*/</title>", re.IGNORECASE),
]
Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a new branch for your feature or bugfix.
Submit a pull request.
License
This project is licensed under the MIT License. See the LICENSE file for details.

Disclaimer
This tool is intended for ethical use only. Ensure you have proper authorization before scanning networks or systems. Misuse may violate laws and regulations in your jurisdiction. The developers assume no responsibility for improper use.

Author
Developed by a cybersecurity student passionate about scalable and efficient tools. Feel free to reach out with questions or feedback!
