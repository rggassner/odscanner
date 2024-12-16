#! venv/bin/python
import sqlite3
import re
db_file = 'scan_results.db'
url_regex = r"https?://[^\s\"'>]+"
def extract_links_from_db():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS extracted_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_result_id INTEGER NOT NULL,
            link TEXT NOT NULL,
            UNIQUE(scan_result_id, link),
            FOREIGN KEY(scan_result_id) REFERENCES scan_results(id)
        );
    """)
    conn.commit()
    cursor.execute("SELECT id, webpage_content FROM scan_results WHERE webpage_content IS NOT NULL")
    rows = cursor.fetchall()
    for row_id, content in rows:
        links = re.findall(url_regex, content)
        for link in links:
            cursor.execute("""
                INSERT OR IGNORE INTO extracted_links (scan_result_id, link)
                VALUES (?, ?);
            """, (row_id, link))
    conn.commit()
    conn.close()
    print("Links extracted and saved to the database.")
if __name__ == "__main__":
    extract_links_from_db()
