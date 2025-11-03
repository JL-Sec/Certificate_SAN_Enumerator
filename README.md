# Certificate SAN Enumerator
A simple bash tool to enumerate all SANs associated with a certificate

# certificat_SAN_enum.sh

`certificate_SAN_enum.sh` — a simple certificate enumeration tool that uses `nmap` and `openssl` to discover certificate CNs, SANs, and fingerprints, and optionally resolves SAN hostnames into A/AAAA records.

---

# Example Output

![Example Output](EXAMPLE%20OUTPUT2.png)

### Example of Exported CSV

![Example Output](EXAMPLE%20OUTPUT.png)

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
git clone https://github.com/JL-Sec/Certificate_SAN_Enumerator.git
cd cert-enum
chmod +x certificate_SAN_enum.sh
```

## Examples

# Single target (defaults to port 443)
./certificate_SAN_enum.sh example.com -o certs.csv

# Single IP:port
./certificate_SAN_enum.sh 10.10.10.10:5061 -o certs.csv

# From file (supports comments '#')
./certificate_SAN_enum.sh -i targets.txt -o results.csv

# With SAN DNS resolution (creates results_sans.csv)
./certificate_SAN_enum.sh -i targets.txt -o results.csv --resolve
