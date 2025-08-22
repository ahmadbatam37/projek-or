#!/bin/bash
# Pindah ke direktori skrip agar output disimpan di lokasi yang benar
script_dir="$(dirname "$(realpath "$0")")"
cd "$script_dir" || exit 1

input_file="$1"
session_id="$2"
export OR_SESSION_ID="$session_id"
# Validasi input file
if [[ ! -f "$1" ]]; then
  echo "⚠ File input tidak ditemukan: $1"
  exit 1
fi

# Buat timestamp unik + folder output
timestamp="$(date +"%Y%m%d-%H%M%S")_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
output_dir="scan_${timestamp}"
mkdir -p "$output_dir"

logfile="$output_dir/full_output_${timestamp}.log"
cleanlog="$output_dir/clean_output_${timestamp}.log"
outputfile="$output_dir/vuln_urls_${timestamp}.txt"

# Ubah path input menjadi absolut dan ekspor ke ENV
export INPUTFILE="$(realpath "$1")"

# Buat skrip expect sementara
expect_tmp=$(mktemp)
cat > "$expect_tmp" <<'EOF'
#!/usr/bin/expect -f
set timeout -1
cd ~/Downloads/loxs
spawn python3 loxs.py
expect "Select an option" { send "2\r" }
expect "Enter the path to the input file containing the URLs" { send "[file normalize $env(INPUTFILE)]\r" }
expect "Enter the path to the payloads file" { send "payloads/or.txt\r" }
expect "Enter the number of concurrent threads" { send "5\r" }
expect "Do you want to generate an HTML report" { send "n\r" }
expect "Select an option" { send "7\r" }
expect eof
EOF

chmod +x "$expect_tmp"

# Jalankan dan rekam output
script -q -c "$expect_tmp" "$logfile"

# Bersihkan warna terminal dari log
sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$logfile" > "$cleanlog"

# Ambil bagian [+] Vulnerable URLs
awk '
/^\[\+\] Vulnerable URLs:/ {capture=1; next}
capture && /^\[/ {capture=0}
capture && /https?:\/\// {gsub(/^[ \t]+/, "", $0); print}
' "$cleanlog" > "$outputfile"

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

# Bersihkan file sementara
rm -f "$expect_tmp"

# ─────────────────────────────────────────────────────
# Sinkronisasi file output agar benar-benar tersimpan
sync && sleep 1

# Bersihkan karakter CRLF (Windows-style) dari hasil scan
dos2unix "$outputfile" 2>/dev/null

# ─────────────────────────────────────────────────────
echo
echo "[→] Menjalankan fallback scan dengan Xray..."
input_folder="$(dirname "$INPUTFILE")"
original_file="$input_folder/open_redirect_output.txt"

if [[ ! -f "$original_file" ]]; then
  echo "⚠ File open_redirect_output.txt tidak ditemukan di folder input: $input_folder"
  echo "⚠ Fallback Xray dilewati."
  final_input="$outputfile"
else
  "$script_dir/fallback_xray_scanbaru.sh" "$outputfile" "$original_file" "$session_id"

  xray_result_file="$HOME/Documents/projek-or/open_redirect/fallback_${session_id}/xray_redirect.txt"
  if [[ -f "$xray_result_file" && -s "$xray_result_file" ]]; then
    echo "[+] Menggabungkan hasil Loxs dan Xray..."
    fallback_output="$output_dir/xray_vuln_merged_${timestamp}.txt"
    cat "$outputfile" "$xray_result_file" | sort -u > "$fallback_output"
    final_input="$fallback_output"
  else
    final_input="$outputfile"
  fi
fi

# ✨ Validasi akhir
echo
echo "[→] Melanjutkan validasi akhir..."
dos2unix "$final_input" 2>/dev/null
"$script_dir/validate_or_summarybk.sh" "$final_input"
