#!/usr/bin/env bash
# TLS certificate enumerator (nmap + openssl) with optional SAN resolution and exploded SAN CSV
# Requirements: openssl, nmap, sed, awk, grep, timeout (coreutils)

set -euo pipefail

# Defaults
OUTFILE="cert_enum_results.csv"
TMPDIR=$(mktemp -d /tmp/cert_enum.XXXX)
NMAP_OUTDIR="${TMPDIR}/nmap"
mkdir -p "${NMAP_OUTDIR}"
TIMEOUT_SECS=12
DO_RESOLVE=0

usage() {
  cat <<EOF

certificate_SAN_enum.sh - TLS certificate enumerator (nmap + openssl)
Generates: main CSV (certs) and optional exploded SAN CSV when --resolve is used.

Usage:
  ./certificate_SAN_enum.sh [options] [targets]
  ./certificate_SAN_enum.sh -i targets.txt -o results.csv --resolve

Targets:
  - single inline:  10.10.10.10:5061
  - multiple inline: 10.10.10.10:5061,10.10.20.20:443
  - host only: example.com          (defaults to port 443)
  - with explicit SNI: 1.2.3.4:443:host.example.com

Options:
  -i FILE        Input file (one target per line or comma-separated)
  -o FILE        Output CSV for certs (default: ${OUTFILE})
  -t SECS        Timeout for openssl s_client (default: ${TIMEOUT_SECS})
  --resolve      Resolve SAN hostnames to A/AAAA and create <OUTFILE>_sans.csv
  -h             Show this help and examples

Examples:
  # Basic single target (cert enumeration only)
  ./certificate_SAN_enum.sh 10.10.10.10:5061 -o certs.csv

  # Multiple inline targets, default port if omitted
  ./certificate_SAN_enum.sh 10.10.10.10:5061,example.com:443 -o results.csv

  # From file (comments with '#' and blank lines allowed)
  ./certificate_SAN_enum.sh -i targets.txt -o results.csv

  # With SNI (target is IP but you want specific SNI)
  ./certificate_SAN_enum.sh 1.2.3.4:443:host.example.com --resolve

  # Full workflow: enumerate certs + resolve SANs -> exploded SAN CSV produced
  ./certificate_SAN_enum.sh -i targets.txt -o myresults.csv --resolve

Note:
  - nmap --script ssl-cert is active testing (performs TLS handshake). Only run on in-scope targets.
  - The script prints per-target summaries while running and writes CSVs to disk.
EOF
  exit 1
}

# Parse args
INPUT_LIST=""
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -i)
      INPUT_FILE="$2"; shift; shift
      ;;
    -o)
      OUTFILE="$2"; shift; shift
      ;;
    -t)
      TIMEOUT_SECS="$2"; shift; shift
      ;;
    --resolve)
      DO_RESOLVE=1; shift
      ;;
    -h)
      usage
      ;;
    --) shift; break
      ;;
    *)
      if [ -z "${INPUT_LIST}" ]; then INPUT_LIST="$1"; else INPUT_LIST="$INPUT_LIST,$1"; fi
      shift
      ;;
  esac
done

# If input file provided, read and append
if [ ! -z "${INPUT_FILE:-}" ] && [ -f "${INPUT_FILE:-}" ]; then
  filecontent=$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$INPUT_FILE" | tr '\n' ',' | sed 's/,$//')
  if [ -z "${INPUT_LIST}" ]; then
    INPUT_LIST="$filecontent"
  else
    INPUT_LIST="${INPUT_LIST},${filecontent}"
  fi
fi

# Normalize and validate input
INPUT_LIST=$(echo "$INPUT_LIST" | sed 's/^,//; s/,$//')
if [ -z "${INPUT_LIST}" ]; then
  echo "[!] No targets specified."
  usage
fi

IFS=',' read -r -a TARGETS <<< "$INPUT_LIST"

# Prepare CSV headers
printf '%s\n' "host,port,sni_used,cn,sans,sha1_fingerprint,issuer,nmap_output" > "$OUTFILE"
if [ $DO_RESOLVE -eq 1 ]; then
  SAN_OUTFILE="${OUTFILE%.csv}_sans.csv"
  printf '%s\n' "parent_host,parent_port,cn,san_name,a_ips,aaaa_ips,status" > "$SAN_OUTFILE"
fi

# csv quote helper
csvq() {
  local s="$1"; s="${s//\"/\"\"}"; printf '"%s"' "$s"
}

# DNS resolver preference
have_dig=0; have_nslookup=0
command -v dig >/dev/null 2>&1 && have_dig=1
command -v nslookup >/dev/null 2>&1 && have_nslookup=1

resolve_dns_pair() {
  local name="$1"
  local A="" AAAA=""
  if [ $have_dig -eq 1 ]; then
    A=$(dig +short A "$name" 2>/dev/null | tr '\n' ' ' | xargs || true)
    AAAA=$(dig +short AAAA "$name" 2>/dev/null | tr '\n' ' ' | xargs || true)
  elif [ $have_nslookup -eq 1 ]; then
    A=$(nslookup -type=A "$name" 2>/dev/null | awk '/^Address: /{print $2}' | tr '\n' ' ' | xargs || true)
    AAAA=$(nslookup -type=AAAA "$name" 2>/dev/null | awk '/^Address: /{print $2}' | tr '\n' ' ' | xargs || true)
  else
    echo "NXDOMAIN"
    return
  fi
  if [ -z "$A" ] && [ -z "$AAAA" ]; then
    echo "NXDOMAIN"
  else
    echo "${A}||${AAAA}"
  fi
}

# Main loop
for raw in "${TARGETS[@]}"; do
  target=$(echo "$raw" | tr -d '[:space:]')
  [ -z "$target" ] && continue

  IFS=':' read -r part1 part2 part3 <<< "$target"
  host="$part1"
  port="${part2:-443}"
  sni="${part3:-$host}"

  echo
  echo "[*] Target: ${host}:${port}  (SNI=${sni})"
  nmapfile="${NMAP_OUTDIR}/${host//:/_}_${port}.nmap.txt"
  xmlout="${NMAP_OUTDIR}/${host//:/_}_${port}.nmap.xml"

  echo "[>] Running nmap --script ssl-cert ..."
  nmap -p "${port}" --script ssl-cert -oN "${nmapfile}" -oX "${xmlout}" -Pn "${host}" >/dev/null 2>&1 || true

  cert_pem="${TMPDIR}/${host//:/_}_${port}_${sni}.pem"
  timeout "${TIMEOUT_SECS}"s openssl s_client -connect "${host}:${port}" -servername "${sni}" -showcerts </dev/null 2>/dev/null || true \
    | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "${cert_pem}" || true

  if [ ! -s "${cert_pem}" ]; then
    echo "[!] openssl returned no cert with SNI=${sni}. Trying without SNI..."
    timeout "${TIMEOUT_SECS}"s openssl s_client -connect "${host}:${port}" -showcerts </dev/null 2>/dev/null || true \
      | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "${cert_pem}" || true
  fi

  CN=""; SANS=""; SHA1=""; ISSUER=""
  if [ -s "${cert_pem}" ]; then
    awk '/-----BEGIN CERTIFICATE-----/{flag=1} flag{print} /-----END CERTIFICATE-----/{exit}' "${cert_pem}" > "${cert_pem}.leaf"
    certleaf="${cert_pem}.leaf"

    subj=$(openssl x509 -in "${certleaf}" -noout -subject 2>/dev/null || true)
    CN=$(echo "$subj" | sed -n 's/^.*CN=//p' | sed 's#/.*##' | sed 's/,$//' | awk '{print $1}' | sed 's/,$//')
    if [ -z "$CN" ]; then
      CN=$(openssl x509 -in "${certleaf}" -noout -subject -nameopt RFC2253 2>/dev/null | sed -n 's/^subject=.*CN=\([^,]*\).*$/\1/p' || true)
    fi

    SANS=$(openssl x509 -in "${certleaf}" -noout -text 2>/dev/null | awk '/Subject Alternative Name/{getline; print}' || true)
    SANS=$(echo "${SANS}" | sed -e 's/DNS://g' -e 's/ *, */,/g' -e 's/^[ \t]*//;s/[ \t]*$//' | tr -d '\r')

    SHA1=$(openssl x509 -in "${certleaf}" -noout -fingerprint -sha1 2>/dev/null | sed 's/^.*=//; s/://g' || true)
    ISSUER=$(openssl x509 -in "${certleaf}" -noout -issuer 2>/dev/null | sed 's/^issuer= //; s/^[ \t]*//; s/[ \t]*$//' || true)
  else
    echo "[!] No certificate fetched for ${host}:${port}"
  fi

  if [ -z "$SANS" ] && [ -f "$nmapfile" ]; then
    SANS=$(grep -i "Subject Alternative Name" -A1 "$nmapfile" 2>/dev/null | tail -n1 | sed -e 's/DNS://g' -e 's/ *, */,/g' -e 's/^[ \t]*//;s/[ \t]*$//' || true)
  fi

  echo "[+] CN: ${CN:-<none>}"
  echo "[+] SANs: ${SANS:-<none>}"
  echo "[+] Issuer: ${ISSUER:-<none>}"
  echo "[+] SHA1: ${SHA1:-<none>}"
  echo "[+] nmap output: ${nmapfile}"

  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csvq "$host")" "$(csvq "$port")" "$(csvq "$sni")" \
    "$(csvq "$CN")" "$(csvq "$SANS")" "$(csvq "$SHA1")" "$(csvq "$ISSUER")" "$(csvq "$nmapfile")" \
    >> "$OUTFILE"

  if [ $DO_RESOLVE -eq 1 ] && [ -n "$SANS" ]; then
    IFS=',' read -r -a san_list <<< "$SANS"
    for san_name in "${san_list[@]}"; do
      san_name=$(echo "$san_name" | xargs)
      [ -z "$san_name" ] && continue

      resolve_result=$(resolve_dns_pair "$san_name")
      if [ "$resolve_result" = "NXDOMAIN" ]; then
        a_ips=""; aaaa_ips=""; status="NXDOMAIN"
      else
        a_ips="${resolve_result%%||*}"
        aaaa_ips="${resolve_result##*||}"
        status="OK"
      fi

      printf '%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csvq "$host")" "$(csvq "$port")" "$(csvq "$CN")" \
        "$(csvq "$san_name")" "$(csvq "$a_ips")" "$(csvq "$aaaa_ips")" "$(csvq "$status")" \
        >> "$SAN_OUTFILE"

      echo "    -> ${san_name} => ${status} ${a_ips:+A:${a_ips}} ${aaaa_ips:+AAAA:${aaaa_ips}}"
    done
  fi

done

echo
echo "[*] Done."
echo "[*] Main CSV: $OUTFILE"
if [ $DO_RESOLVE -eq 1 ]; then
  echo "[*] Exploded SAN CSV: $SAN_OUTFILE"
fi
echo "[*] Nmap outputs saved to: $NMAP_OUTDIR"
echo "[*] Temp files are in: $TMPDIR (delete when you no longer need them)"
