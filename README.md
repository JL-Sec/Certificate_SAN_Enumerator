# Certificate_SAN_Enumerator
A simple bash tool to enumerate all SANs associated with a certificate

# cert_enum.sh

`cert_enum.sh` — a simple certificate enumeration tool that uses `nmap` and `openssl` to discover certificate CNs, SANs, and fingerprints, and optionally resolves SAN hostnames into A/AAAA records for follow-on scanning.

> **Purpose**: quickly enumerate TLS certificates for external targets, extract SANs (including those only revealed by `nmap --script ssl-cert`), and creates CSV output.

---

## Features

- Runs `nmap --script ssl-cert` per target to collect CN/SAN even when SNI unknown.  
- Uses `openssl s_client` to fetch the leaf certificate and extract issuer, CN, SANs, and SHA1 fingerprint.  
- Optionally resolves each SAN to A/AAAA (using `dig` or `nslookup`) and writes a SAN CSV (one row per SAN).  
- Prints progress and summaries to the console while writing CSV output.  
- Output:
  - `results.csv` — certificate-level summary (one row per target).
  - `results_sans.csv` — expanded SANs (one row per SAN) when `--resolve` is enabled.

---

## Requirements

- `bash` (Linux/macOS)
- `nmap`

---

## Installation

Just download or clone this repo and make the script executable:

```bash
git clone <your-repo-url>
cd cert-enum
chmod +x cert_enum.sh
```

## Examples

# Single target (defaults to port 443)
./cert_enum.sh example.com -o certs.csv

# Single IP:port
./cert_enum.sh 10.10.10.10:5061 -o certs.csv

# Multiple inline targets
./cert_enum.sh 10.10.10.10:5061,example.com:443 -o results.csv

# From file (supports comments '#')
./cert_enum.sh -i targets.txt -o results.csv

# With SAN DNS resolution (creates results_sans.csv)
./cert_enum.sh -i targets.txt -o results.csv --resolve

# With explicit SNI when target is an IP
./cert_enum.sh 1.2.3.4:443:host.example.com --resolve

