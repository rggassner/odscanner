import re
from ipaddress import IPv4Address, IPv4Network


DB_NAME = "scan_results.db"
TABLE_NAME = "scan_results"

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
    re.compile(r"<h1>文件索引.*?</h1>", re.IGNORECASE),
    re.compile(r"Directory listing for .*", re.IGNORECASE),    
    re.compile(r"<ListBucketResult\s+xmlns=['\"].*?['\"]>", re.IGNORECASE),
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
