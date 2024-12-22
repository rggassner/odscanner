# Async IP and Port Scanner - port_scan.py

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
     
    ```bash
    git clone https://github.com/rggassner/odscanner.git
    cd odscanner
    ```
    
3.  Set up a virtual environment and activate it:
    
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```
    
5.  Install dependencies:
    
    ```bash
    pip install -r requirements.txt
    ```
    
7.  Place the `nmap-services` file at `/usr/share/nmap/nmap-services`. Modify `file_path` in the script if the file is located elsewhere.
    
8.  Initialize the SQLite database:
    
    ```bash
    python -m port_scan.py --setup-db
    ```
    

## Usage

Run the script with:

   ```bash
   python port_scan.py
   ```

### Options

-   `-v`, `--verbose`: Enable verbose output for debugging.

Example:

   ```bash
   python port_scan.py -v
   ```

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


# IPv4 Address Space Visualization - image.py

This Python script visualizes the IPv4 address space on a per-/24 network basis, using data from an SQLite database. It creates a 4096x4096 pixel image where each pixel corresponds to a /24 network in the IPv4 address space, with colors representing the network's status:

- **Gray:** Excluded networks (e.g., private, reserved, or non-routable ranges).
- **Green:** Networks with at least one active entry (`retired=0`) in the database.
- **Red:** Networks where all entries are marked as `retired=1`.
- **White:** Networks with no entries in the database.

## Features

- **Visualization of IPv4 /24 Networks:** Each pixel represents a /24 network in the IPv4 address space.
- **Database Integration:** Fetches data from an SQLite database (`scan_results.db`) to determine network statuses.
- **Excluded Networks:** Automatically excludes private, reserved, or non-routable ranges.
- **Color-Coding:**
  - Gray: Excluded networks.
  - Green: Active networks.
  - Red: Retired networks.
  - White: Networks with no entries.

## Prerequisites

- Python 3.8+
- `Pillow` library for image processing:
- 
  ```bash
  pip install pillow
  ```

  
-   SQLite database file (`scan_results.db`) with the following schema:
    
```sql
CREATE TABLE scan_results (     ip TEXT NOT NULL,     retired INTEGER NOT NULL );
```
    

## Key Functions

1.  **`is_excluded(network_id)`**  
    Determines if a given /24 network belongs to an excluded range (e.g., private or reserved ranges).
    
2.  **`ip_to_int(ip)`**  
    Converts an IPv4 address string to a 32-bit integer for processing.
    
3.  **`fetch_network_status(cursor)`**  
    Queries the database to retrieve the retired status of IPs, grouped by /24 networks, and determines their visual status.
    
4.  **`generate_ipv4_network_image(size, db_path)`**  
    Creates a 4096x4096 pixel image representing the IPv4 /24 networks based on database data, with the pixel color reflecting the network's status.
    

## Output

-   A PNG image (`ipv4_networks_colored.png`) that visually represents the IPv4 /24 network status.

## Usage

1.  Ensure you have the required SQLite database (`scan_results.db`) in the script's directory.
2.  Run the script:
    
    ```bash
    python image.py
    ```
    
4.  The resulting image (`ipv4_networks_colored.png`) will be saved in the current directory.

## Example Image

Each pixel in the 4096x4096 grid corresponds to a /24 network in the IPv4 space:

-   **Gray:** Excluded networks (e.g., 10.0.0.0/8, 127.0.0.0/8).
-   **Green:** Networks with at least one active (non-retired) entry.
-   **Red:** Networks where all entries are retired.
-   **White:** Networks with no database entries.

Explore the current state of IPv4 address space with this easy-to-use script.

# Scan Results Web App - report.py

This is a Flask web application for displaying and managing scan results from a database. The app connects to an SQLite database (`scan_results.db`) and presents the data in an interactive format with sorting, pie charts, and the ability to retire certain scan results.

## Features

- **Display Scan Results**: The app presents scan results in tables with sortable columns.
- **Retire Scan Results**: You can retire specific scan results based on their IP address.
- **Interactive Pie Charts**: The app generates several pie charts that show the distribution of scan data, such as:
  - Total scans vs. found
  - Protocol distribution
  - Status code distribution
  - Unexpected service port distribution
- **Responsive Design**: The app is responsive and adjusts the layout for different screen sizes.

## Installation

To run this application, follow the steps below:

### 1. Clone the repository:

```bash
git clone https://github.com/rggassner/odscanner.git
cd odscanner
```

### 2\. Set up a virtual environment:

```bash
python3 -m venv venv source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

### 3\. Install the required dependencies:

```bash
pip install -r requirements.txt
```

Make sure you have `Flask` and `sqlite3` installed in your environment.

### 4\. Database Setup

Ensure that the `scan_results.db` database is present and contains the appropriate data. The database should have a table `scan_results` with the following columns:

-   `id`
-   `ip`
-   `port`
-   `protocol`
-   `path`
-   `status_code`
-   `redirect_url`
-   `is_open_directory`
-   `last_scanned`
-   `retired`

You can modify the database schema and data based on your specific needs.

## Running the Application

Once the environment is set up, run the app with the following command:

```bash
python app.py
```

This will start the Flask development server, and the app will be available at `http://127.0.0.1:5000/` by default.

## Usage

### Web Interface

-   **Sort Tables**: Click on any column header in the tables to sort by that column.
-   **Retire Scan Results**: Click on the "Retire" button next to any scan result to mark it as retired.
-   **Pie Charts**: The app will generate pie charts based on the scan data, which you can use to analyze the distribution of protocols, status codes, ports, and more.

### Retiring Scan Results

When you click "Retire" for a scan result, the IP of the selected result is marked as retired in the database. This helps keep track of processed results.

### Data Visualization

The pie charts provide a visual summary of the scan results:

-   **Total Scans vs. Found**: Displays the number of found vs. unfound services.
-   **Protocol Distribution**: Shows the distribution of protocols in the scan results.
-   **Status Code Distribution**: Shows how the scan results are distributed by HTTP status codes.
-   **Unexpected Service Port Distribution**: Shows the distribution of ports where unexpected services were found.



  

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Feel free to submit issues or pull requests to improve the script!

## Disclaimer

This script is for educational and research purposes only. Ensure you have permission to scan any IP addresses before use.
