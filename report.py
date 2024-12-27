#!venv/bin/python3
from flask import Flask, render_template_string, request, jsonify
import sqlite3
from jinja2 import Template

app = Flask(__name__)

#Define database path and HTML template
db_path = "scan_results.db"
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Results</title>
    <style>
    .github-link-container {
    text-align: center;
    margin-top: 40px;
    padding: 20px;
}

.github-link {
    text-decoration: none;
    color: #333;
    font-size: 16px;
    font-weight: bold;
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 10px;
}

.github-link:hover {
    color: #0366d6;  /* GitHub blue on hover */
}

.github-icon {
    width: 30px;  /* Size of the GitHub icon */
    height: 30px;
    transition: transform 0.3s ease;
}

.github-link:hover .github-icon {
    transform: scale(1.2);  /* Slight enlargement on hover */
}

        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }

        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }

        th {
            background-color: #4CAF50;
            color: white;
            cursor: pointer;
        }

        tr:nth-child(even) {
            background-color: #f2f2f2;
        }

        tr:hover {
            background-color: #ddd;
        }

        /* Container for the pie charts */
        .pie-chart-container {
            display: flex;
            justify-content: space-between;  /* Space out the pie charts */
            flex-wrap: wrap;  /* Allow wrapping on smaller screens */
            gap: 20px;  /* Add space between the charts */
            padding: 20px;
            box-sizing: border-box;
        }

        .pie-chart {
            flex: 1 1 calc(25% - 20px); /* Make each pie chart take up 1/3 of the width, minus gap */
            max-width: calc(25% - 20px); /* Ensure they don't exceed this width */
            box-sizing: border-box;
        }

        /* Responsive for smaller screens */
        @media (max-width: 768px) {
            .pie-chart {
                flex: 1 1 100%;  /* Stack charts vertically on small screens */
                max-width: 100%;
            }
        }
    </style>
     <script>
        // JavaScript function to update the "retired" status
        function retireRow(ip) {
            fetch(`/retire`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ ip: ip }),
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(`Successfully retired rows for IP: ${ip}`);
                    location.reload(); // Refresh the page
                } else {
                    alert(`Failed to retire rows for IP: ${ip}`);
                }
            });
        }
    </script>
</head>
<body>
    <h1>Scan Results</h1>

    <h2>Unexpected Internet Services</h2>
    <table id="table1">
        <thead>
            <tr>
                <th onclick="sortTable(0, 'table1')">ID</th>
                <th onclick="sortTable(1, 'table1')">URL</th>
                <th onclick="sortTable(2, 'table1')">Status Code</th>
                <th onclick="sortTable(3, 'table1')">Redirect URL</th>
                <th onclick="sortTable(4, 'table1')">Open Directory</th>
                <th onclick="sortTable(5, 'table1')">Last Scanned</th>
                <th onclick="sortTable(6, 'table1')">Retired</th>
            </tr>
        </thead>
        <tbody>
            {% for row in data1 %}
            <tr>
                <td>{{ row[0] }}</td>
                <td><a href="{{ row[3] }}://{{ row[1] }}:{{ row[2] }}/{{ row[4] }}" target="_blank">{{ row[3] }}://{{ row[1] }}:{{ row[2] }}/{{ row[4] }}</a></td>
                <td>{{ row[5] }}</td>
                <td>{{ row[6] }}</td>
                <td>{{ row[7] }}</td>
                <td>{{ row[8] }}</td>
                <td>{{ row[9] }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <h2>Open Directories</h2>
    <table id="table2">
        <thead>
            <tr>
                <th onclick="sortTable(0, 'table2')">ID</th>
                <th onclick="sortTable(1, 'table2')">URL</th>
                <th onclick="sortTable(2, 'table2')">Status Code</th>
                <th onclick="sortTable(3, 'table2')">Redirect URL</th>
                <th onclick="sortTable(4, 'table2')">Open Directory</th>
                <th onclick="sortTable(5, 'table2')">Last Scanned</th>
                <th onclick="sortTable(6, 'table2')">Retired</th>
            </tr>
        </thead>
        <tbody>
            {% for row in data2 %}
            <tr>
                <td>{{ row[0] }}</td>
                <td><a href="{{ row[3] }}://{{ row[1] }}:{{ row[2] }}/{{ row[4] }}" target="_blank">{{ row[3] }}://{{ row[1] }}:{{ row[2] }}/{{ row[4] }}</a></td>
                <td>{{ row[5] }}</td>
                <td>{{ row[6] }}</td>
                <td>{{ row[7] }}</td>
                <td>{{ row[8] }}</td>
                <td>{{ row[9] }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>



<h2>Pie Charts:</h2>
<div class="pie-chart-container">
    <div class="pie-chart">
        <p class="pie-description">Total scans vs. found</p>
        <canvas id="pieChart"></canvas>
    </div>

    <div class="pie-chart">
        <p class="pie-description">Protocol Distribution</p>
        <canvas id="protocolPieChart"></canvas>
    </div>

    <div class="pie-chart">
        <p class="pie-description">Status Code Distribution</p>
        <canvas id="statusCodePieChart"></canvas>
    </div>
    <div class="pie-chart">
        <p class="pie-description">Unexpected Service Port Distribution</p>
        <canvas id="portPieChart"></canvas>
    </div>
</div>

    <h2>Status Code 200</h2>
    <table id="table3">
        <thead>
            <tr>
                <th onclick="sortTable(0, 'table3')">ID</th>
                <th onclick="sortTable(1, 'table3')">URL</th>
                <th onclick="sortTable(2, 'table3')">Status Code</th>
                <th onclick="sortTable(3, 'table3')">Redirect URL</th>
                <th onclick="sortTable(4, 'table3')">Open Directory</th>
                <th onclick="sortTable(5, 'table3')">Last Scanned</th>
                <th onclick="sortTable(6, 'table3')">Retired</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            {% for row in data3 %}
            <tr>
                <td>{{ row[0] }}</td>
                <td><a href="{{ row[3] }}://{{ row[1] }}:{{ row[2] }}/{{ row[4] }}" target="_blank">{{ row[3] }}://{{ row[1] }}:{{ row[2] }}/{{ row[4] }}</a></td>
                <td>{{ row[5] }}</td>
                <td>{{ row[6] }}</td>
                <td>{{ row[7] }}</td>
                <td>{{ row[8] }}</td>
                <td>{{ row[9] }}</td>
                <td><button onclick="retireRow('{{ row[1] }}')">Retire</button></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        var ctx = document.getElementById('pieChart').getContext('2d');
        var pieChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Service Found', 'Service not Found'],
                datasets: [{
                    data: [{{ table3_count }}, {{ other_entries }}],
                    backgroundColor: ['#4CAF50', '#FF5722'],
                    hoverOffset: 4
                }]
            }
        });

        var protocolCtx = document.getElementById('protocolPieChart').getContext('2d');
        var protocolPieChart = new Chart(protocolCtx, {
            type: 'pie',
            data: {
                labels: {{ protocol_labels | tojson }},
                datasets: [{
                    data: {{ protocol_values | tojson }},
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4CAF50', '#FF5722'
                    ],
                    hoverOffset: 4
                }]
            }
        });

        var statusCodeCtx = document.getElementById('statusCodePieChart').getContext('2d');
        var statusCodePieChart = new Chart(statusCodeCtx, {
            type: 'pie',
            data: {
                labels: {{ status_code_labels | tojson }},
                datasets: [{
                    data: {{ status_code_values | tojson }},
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', '#4CAF50', '#FF5722', '#9C27B0', '#FFC107'
                    ],
                    hoverOffset: 4
                }]
            }
        });

        var portCtx = document.getElementById('portPieChart').getContext('2d');
var portPieChart = new Chart(portCtx, {
    type: 'pie',
    data: {
        labels: {{ port_labels | tojson }},
        datasets: [{
            data: {{ port_values | tojson }},
            backgroundColor: [
                '#FF6384', '#36A2EB', '#FFCE56', '#4CAF50', '#FF5722', '#FFC107'
            ],
            hoverOffset: 4
        }]
    }
});

    var lastSortedColumn = -1;  // To keep track of the last sorted column
    var lastSortOrder = "asc";  // To keep track of the last sort order

    function sortTable(columnIndex, tableId) {
        var table = document.getElementById(tableId);
        var rows = Array.from(table.getElementsByTagName("tr")).slice(1); // Skip header row
        var sortedRows;

        // If the same column is clicked, reverse the sorting order
        if (lastSortedColumn === columnIndex) {
            lastSortOrder = lastSortOrder === "asc" ? "desc" : "asc";
        } else {
            lastSortOrder = "asc";  // Default to ascending if a new column is clicked
        }

        // Sort the rows based on the selected column
        sortedRows = rows.sort(function(a, b) {
            var cellA = a.getElementsByTagName("td")[columnIndex].innerText;
            var cellB = b.getElementsByTagName("td")[columnIndex].innerText;
            
            // Handle numeric sorting
            if (!isNaN(cellA) && !isNaN(cellB)) {
                return lastSortOrder === "asc" 
                    ? parseFloat(cellA) - parseFloat(cellB) 
                    : parseFloat(cellB) - parseFloat(cellA);
            }

            // Handle alphanumeric sorting
            return lastSortOrder === "asc"
                ? cellA.localeCompare(cellB)
                : cellB.localeCompare(cellA);
        });

        // Re-append the rows to the table after sorting
        sortedRows.forEach(function(row) {
            table.appendChild(row);
        });

        // Update the last sorted column
        lastSortedColumn = columnIndex;
    }

    </script>
<!-- GitHub Link with Icon -->
<div class="github-link-container">
    <a href="https://github.com/rggassner/odscanner/" target="_blank" class="github-link">
        <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/9/91/Octicons-mark-github.svg/1024px-Octicons-mark-github.svg.png" alt="GitHub" class="github-icon">
        <span>Visit the project on GitHub</span>
    </a>
</div>
</body>
</html>
"""

# Function to execute a query and fetch data
def fetch_data(query):
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    data = cursor.execute(query).fetchall()
    connection.close()
    return data

# Function to execute a query to modify the database
def execute_query(query, params=()):
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute(query, params)
    connection.commit()
    connection.close()

@app.route("/retire", methods=["POST"])
def retire():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"success": False, "error": "No IP provided"}), 400
    
    try:
        query = "UPDATE scan_results SET retired = 1 WHERE ip = ?"
        execute_query(query, (ip,))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    #If you want to remove the retired for accessible any ips
    #UPDATE scan_results SET retired = 0 WHERE retired = 1 AND not (status_code IS NULL OR status_code = '');

@app.route("/")
def scan_results():
    query1 = """
    SELECT id, ip, port, protocol, path, status_code, redirect_url, is_open_directory, last_scanned, retired
    FROM scan_results
    WHERE NOT (port = 80 AND protocol = 'http') AND NOT (port = 443 AND protocol = 'https') AND (status_code LIKE '2%' OR status_code LIKE '3%');
    """

    query2 = """
    SELECT id, ip, port, protocol, path, status_code, redirect_url, is_open_directory, last_scanned, retired
    FROM scan_results
    WHERE status_code IS NOT NULL AND is_open_directory = 1;
    """

    query3 = """
    SELECT id, ip, port, protocol, path, status_code, redirect_url, is_open_directory, last_scanned, retired,
       COUNT(*) OVER (PARTITION BY ip) AS ip_count
FROM scan_results
WHERE (status_code LIKE '2%' OR status_code LIKE '3%')
  AND retired = 0
  AND (redirect_url IS NULL OR redirect_url = '')
ORDER BY ip_count DESC, ip;
    """
    port_counts = fetch_data("""
    SELECT port, COUNT(*) 
    FROM scan_results 
    WHERE NOT (port = 80 AND protocol = 'http') 
      AND NOT (port = 443 AND protocol = 'https') 
      AND status_code IS NOT NULL
    GROUP BY port;
    """)

    port_labels = [str(row[0]) for row in port_counts]
    port_values = [row[1] for row in port_counts]
    data1 = fetch_data(query1)
    data2 = fetch_data(query2)
    data3 = fetch_data(query3)

    # Calculate counts for the pie charts
    def get_count(query):
        connection = sqlite3.connect(db_path)
        cursor = connection.cursor()
        count = cursor.execute(query).fetchone()[0]
        connection.close()
        return count

    total_entries = get_count("SELECT COUNT(*) FROM scan_results;")
    table3_count = get_count("SELECT COUNT(*) FROM scan_results WHERE status_code IS NOT NULL;")
    other_entries = total_entries - table3_count

    # Fetch protocol counts for Table 3
    protocol_counts = fetch_data("""
    SELECT protocol, COUNT(*) 
    FROM scan_results 
    WHERE status_code IS NOT NULL 
    GROUP BY protocol;
    """)
    protocol_labels = [row[0] for row in protocol_counts]
    protocol_values = [row[1] for row in protocol_counts]
    
    # Fetch status code counts for Table 3
    status_code_counts = fetch_data("""
    SELECT status_code, COUNT(*)
    FROM scan_results
    WHERE status_code IS NOT NULL
    GROUP BY status_code;
    """)
    status_code_labels = [str(row[0]) for row in status_code_counts]
    status_code_values = [row[1] for row in status_code_counts]

    # Prepare tables HTML content
    def render_table(data, table_id):
        return """
        <h2>Table {{ table_id }}: Data</h2>
        <table id="table{{ table_id }}">
            <thead>
                <tr>
                    <th onclick="sortTable(0, 'table{{ table_id }}')">ID</th>
                    <th onclick="sortTable(1, 'table{{ table_id }}')">URL</th>
                    <th onclick="sortTable(2, 'table{{ table_id }}')">Status Code</th>
                    <th onclick="sortTable(3, 'table{{ table_id }}')">Redirect URL</th>
                    <th onclick="sortTable(4, 'table{{ table_id }}')">Open Directory</th>
                    <th onclick="sortTable(5, 'table{{ table_id }}')">Last Scanned</th>
                    <th onclick="sortTable(6, 'table{{ table_id }}')">Retired</th>
                </tr>
            </thead>
            <tbody>
                {% for row in data %}
                <tr>
                    <td>{{ row[0] }}</td>
                    <td><a href="{{ row[3] }}://{{ row[1] }}:{{ row[2] }}/{{ row[4] }}" target="_blank">{{ row[3] }}://{{ row[1] }}:{{ row[2] }}/{{ row[4] }}</a></td>
                    <td>{{ row[5] }}</td>
                    <td>{{ row[6] }}</td>
                    <td>{{ row[7] }}</td>
                    <td>{{ row[8] }}</td>
                    <td>{{ row[9] }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        """.replace('{{ table_id }}', str(table_id))

    # Render the HTML with Jinja2
    template = Template(html_template)
    return render_template_string(
        html_template,
        data1=data1,
        data2=data2,
        data3=data3,
        table3_count=table3_count,
        other_entries=other_entries,
        protocol_labels=protocol_labels,
        protocol_values=protocol_values,
        status_code_labels=status_code_labels,
        status_code_values=status_code_values,
        port_labels=port_labels,  
        port_values=port_values  
    )

if __name__ == "__main__":
    app.run(debug=True)
# Write the HTML content to a file
#with open("scan_results.html", "w") as html_file:
#    html_file.write(html_content)

#print("HTML file 'scan_results.html' has been generated.")
