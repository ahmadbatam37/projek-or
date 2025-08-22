#!/bin/bash
# Pindah ke direktori skrip agar output disimpan di lokasi yang benar
script_dir="$(dirname "$(realpath "$0")")"
cd "$script_dir" || exit 1

input_file="$1"
session_id="$2"
export XSS_SESSION_ID="$session_id"
# Validasi input file
if [[ ! -f "$input_file" ]]; then
  echo "⚠ File input tidak ditemukan: $input_file"
  exit 1
fi

# Buat timestamp dan folder output
timestamp="$(date +"%Y%m%d-%H%M%S")_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
output_dir="scan_xss_${timestamp}"
mkdir -p "$output_dir"

logfile="$output_dir/full_output_${timestamp}.log"
cleanlog="$output_dir/clean_output_${timestamp}.log"
outputfile="$output_dir/vuln_urls_${timestamp}.txt"

export INPUTFILE="$(realpath "$input_file")"

# === Jalankan Loxs dengan Expect ===
expect_tmp=$(mktemp)
cat > "$expect_tmp" <<'EOF'
#!/usr/bin/expect -f
set timeout -1
cd ~/Downloads/loxs
spawn python3 loxs.py
expect "Select an option" { send "4\r" }
expect -re ".*Enter the path to the input file.*" { send "[file normalize $env(INPUTFILE)]\r" }
expect "Enter the path to the payloads file" { send "payloads/xss.txt\r" }
expect "Enter the timeout duration for each request" { send "\r" }
expect "Do you want to generate an HTML report" { send "n\r" }
expect eof
EOF

chmod +x "$expect_tmp"
script -q -c "$expect_tmp" "$logfile"
sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$logfile" > "$cleanlog"

# Ekstrak URL yang rentan
awk '/^\[✓\] Vulnerable:/ {
  match($0, /(https?:\/\/[^ ]+)/, arr)
  if (arr[1] != "") print arr[1]
}' "$cleanlog" > "$outputfile"

# Cek hasil
if [[ ! -s "$outputfile" ]]; then
  echo "⚠ Tidak ditemukan URL rentan dari hasil Loxs."
  echo "ℹ Folder tetap disimpan: $output_dir"
  rm -f "$expect_tmp"
  exit 0
fi

echo
echo "[✓] Hasil berhasil disimpan di folder: $output_dir"
echo "[📄] - Log lengkap     : $logfile"
echo "[📄] - Log bersih      : $cleanlog"
echo "[📄] - URL rentan      : $outputfile"

rm -f "$expect_tmp"
sync && sleep 1
dos2unix "$outputfile" 2>/dev/null

# === Fallback Xray ===
echo
echo "[→] Menjalankan fallback scan dengan Xray (XSS)..."
input_folder="$(dirname "$INPUTFILE")"
original_file="$input_folder/xss_output.txt"

if [[ ! -f "$original_file" ]]; then
  echo "⚠ File output.txt tidak ditemukan di: $input_folder"
  echo "⚠ Fallback Xray dilewati."
  final_input="$outputfile"
else
  "$script_dir/fallback_xray_xss.sh" "$outputfile" "$original_file" "$session_id"

  xray_result_file="$HOME/Documents/projek-or/xss/fallback_${session_id}/xray_xss.txt"
  if [[ -f "$xray_result_file" && -s "$xray_result_file" ]]; then
    echo "[+] Menggabungkan hasil Loxs dan Xray..."
    fallback_output="$output_dir/xray_vuln_merged_${timestamp}.txt"
    cat "$outputfile" "$xray_result_file" | sort -u > "$fallback_output"
    final_input="$fallback_output"
  else
    final_input="$outputfile"
  fi
fi

echo
echo "[→] Validasi akhir menggunakan Playwright..."
"$script_dir/validate_xss_playwright.sh" "$final_input" "$session_id"

