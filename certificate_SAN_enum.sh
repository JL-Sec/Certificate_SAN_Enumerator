#!/usr/bin/env bash
# cert_enum.sh
# Usage:
#   ./cert_enum.sh -i targets.txt -o results.csv --resolve
#   ./cert_enum.sh 10.10.10.10:443,example.com:8443 -o results.csv --resolve
#
# Requirements: openssl, nmap, sed, awk, grep, timeout (coreutils)
# (tested on Debian/Ubuntu/Kali)

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
Usage: $0 [options] [host:port[,host2:port2...]]
Options:
  -i FILE    Input file containing host:port (one per line or comma-separated)
  -o FILE    Output CSV file (default: ${OUTFILE})
  -t SECS    Timeout seconds for openssl s_client (default: ${TIMEOUT_SECS})
  --resolve  Resolve SAN hostnames to IPs and save an exploded SAN CSV
  -h         Show this help
Input formats supported:
  host
  host:port
  host:port:sni    # optional SNI if host is IP but you want a hostname for SNI
EOF
  exit 1
}

# Parse args
INPUT_LIST=""
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -i)
      INPUT_FILE="$2"
      shift; shift
      ;;
    -o)
      OUTFILE="$2"
      shift; shift
      ;;
    -t)
      TIMEOUT_SECS="$2"
      shift; shift
      ;;
    --resolve)
      DO_RESOLVE=1
      shift
      ;;
    -h)
      usage
      ;;
    *)
      INPUT_LIST="$INPUT_LIST,$1"
      shift
      ;;
  esac
done

# If input file provided, read it
if [ ! -z "${INPUT_FILE:-}" ] && [ -f "${INPUT_FILE:-}" ]; then
  filecontent=$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$INPUT_FILE" | tr '\n' ',' | sed 's/,$//')
  INPUT_LIST="${INPUT_LIST},${filecontent}"
fi

# Trim commas
INPUT_LIST=$(echo "$INPUT_LIST" | sed 's/^,//;s/,$//')

if [ -z "${INPUT_LIST}" ]; then
  echo "No targets specified."
  usage
fi

IFS=',' read -r -a TARGETS <<< "$INPUT_LIST"

# CSV header for main output
printf '%s\n' "host,port,sni_used,cn,sans,sha1_fingerprint,issuer,nmap_output" > "$OUTFILE"

# If resolve enabled, prepare SAN output CSV
if [ $DO_RESOLVE -eq 1 ]; then
  SAN_OUTFILE="${OUTFILE%.csv}_sans.csv"
  printf "parent_host,parent_port,cn,san_name,a_ips,aaaa_ips,status\n" > "$SAN_OUTFILE"
fi

# Helper: quote CSV field (escape double-quotes)
csvq() {
  local s="$1"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}

resolve_dns() {
  local name="$1"
  local a_ips=$(dig +short A "$name" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')
  local aaaa_ips=$(dig +short AAAA "$name" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')

  if [ -z "$a_ips" ] && [ -z "$aaaa_ips" ]; then
    echo "NXDOMAIN"
  else
    echo "$a_ips,$aaaa_ips"
  fi
}

for raw in "${TARGETS[@]}"; do
  target=$(echo "$raw" | tr -d '[:space:]')
  [ -z "$target" ] && continue

  IFS=':' read -r part1 part2 part3 <<< "$target"
  host="$part1"
  port="${part2:-443}"
  sni="${part3:-$host}"

  echo "[*] Processing ${host}:${port}  (SNI=${sni})"

  nmapfile="${NMAP_OUTDIR}/${host//:/_}_${port}.nmap.txt"
  xmlout="${NMAP_OUTDIR}/${host//:/_}_${port}.nmap.xml"

  echo "[*] Running nmap ssl-cert (this may take a few seconds)..."
  nmap -p "${port}" --script ssl-cert -oN "${nmapfile}" -oX "${xmlout}" -Pn "${host}" >/dev/null 2>&1 || true

  cert_pem="${TMPDIR}/${host//:/_}_${port}_${sni}.pem"
  {
    timeout "${TIMEOUT_SECS}"s openssl s_client -connect "${host}:${port}" -servername "${sni}" -showcerts </dev/null 2>/dev/null || true
  } | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "${cert_pem}" || true

  if [ ! -s "${cert_pem}" ]; then
    echo "[!] openssl returned no cert using SNI=${sni}, trying without SNI..."
    {
      timeout "${TIMEOUT_SECS}"s openssl s_client -connect "${host}:${port}" -showcerts </dev/null 2>/dev/null || true
    } | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "${cert_pem}" || true
  fi

  CN=""; SANS=""; SHA1=""; ISSUER=""
  if [ -s "${cert_pem}" ]; then
    awk '/-----BEGIN CERTIFICATE-----/{flag=1} flag{print} /-----END CERTIFICATE-----/{print; exit}' "${cert_pem}" > "${cert_pem}.leaf.pem"
    certleaf="${cert_pem}.leaf.pem"

    subj=$(openssl x509 -in "${certleaf}" -noout -subject 2>/dev/null || true)
    CN=$(echo "$subj" | sed -n 's/^.*CN=//p' | sed 's#/.*##' | sed 's/,$//' | awk '{print $1}' | sed 's/,$//')
    if [ -z "$CN" ]; then
      CN=$(openssl x509 -in "${certleaf}" -noout -subject -nameopt RFC2253 2>/dev/null | sed -n 's/^subject=.*CN=\([^,]*\).*$/\1/p')
    fi

    SANS=$(openssl x509 -in "${certleaf}" -noout -text 2>/dev/null | awk '/Subject Alternative Name/{getline; print}')
    SANS=$(echo "${SANS}" | sed -e 's/DNS://g' -e 's/ *, */,/g' -e 's/^[ \t]*//;s/[ \t]*$//' | tr -d '\r')

    SHA1=$(openssl x509 -in "${certleaf}" -noout -fingerprint -sha1 2>/dev/null | sed 's/^.*=//; s/://g')
    ISSUER=$(openssl x509 -in "${certleaf}" -noout -issuer 2>/dev/null | sed 's/^issuer= //')
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csvq "$host")" "$(csvq "$port")" "$(csvq "$sni")" \
    "$(csvq "$CN")" "$(csvq "$SANS")" "$(csvq "$SHA1")" "$(csvq "$ISSUER")" "$(csvq "$nmapfile")" \
  >> "$OUTFILE"

  if [ $DO_RESOLVE -eq 1 ] && [ -n "$SANS" ]; then
    IFS=',' read -r -a san_list <<< "$SANS"
    for san_name in "${san_list[@]}"; do
      resolve_result=$(resolve_dns "$san_name")
      IFS=',' read -r a_ips aaaa_ips <<< "$resolve_result"
      status="OK"
      if [ "$resolve_result" == "NXDOMAIN" ]; then
        status="NXDOMAIN"
      fi
      printf '%s,%s,%s,%s,%s,%s,%s\n' \
        "$(csvq "$host")" "$(csvq "$port")" "$(csvq "$CN")" \
        "$(csvq "$san_name")" "$(csvq "$a_ips")" "$(csvq "$aaaa_ips")" "$(csvq "$status")" \
      >> "$SAN_OUTFILE"
    done
  fi

done

echo "[*] Done. Main CSV written to: $OUTFILE"
if [ $DO_RESOLVE -eq 1 ]; then
  echo "[*] SAN CSV written to: ${SAN_OUTFILE}"
fi
echo "[*] Nmap outputs saved in: $NMAP_OUTDIR"
echo "[*] Temporary files in: $TMPDIR (cleanup when done)"
