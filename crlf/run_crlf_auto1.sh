#!/bin/bash
# Pindah ke direktori skrip agar output disimpan di lokasi yang benar
script_dir="$(dirname "$(realpath "$0")")"
cd "$script_dir" || exit 1

input_file="$1"
session_id="$2"
export CRLF_SESSION_ID="$session_id"

# Validasi input file
if [[ ! -f "$input_file" ]]; then
  echo "⚠ File input tidak ditemukan: $input_file"
  exit 1
fi

# Buat timestamp dan folder output
timestamp="$(date +"%Y%m%d-%H%M%S")_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
output_dir="scan_crlf_${timestamp}"
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
expect "Select an option" { send "5\r" }
expect -re ".*Enter the path to the input file.*" { send "[file normalize $env(INPUTFILE)]\r" }
expect "Enter the number of concurrent threads" { send "7\r" }
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
echo "[→] Menjalankan fallback scan dengan Nuclei (CRLF)..."
input_folder="$(dirname "$INPUTFILE")"
original_dir="$input_folder"
with_param="$original_dir/crlf_output_with_param.txt"
without_param="$original_dir/crlf_output_without_param.txt"
root_only="$original_dir/crlf_output_root_only.txt"

if [[ ! -f "$with_param" || ! -f "$without_param" || ! -f "$root_only" ]]; then
  echo "⚠ File output.txt tidak ditemukan di: $input_folder"
  echo "⚠ Fallback Nuclei dilewati."
  final_input="$outputfile"
else
  "$script_dir/fallback_nuclei_crlf.sh" "$outputfile" "$with_param" "$without_param" "$root_only" "$session_id"

  nuclei_result_file="$HOME/Documents/projek-or/crlf/fallback_${session_id}/nuclei_crlf.txt"
  if [[ -f "$nuclei_result_file" && -s "$nuclei_result_file" ]]; then
    echo "[+] Menggabungkan hasil Loxs dan Nuclei..."
    fallback_output="$output_dir/nuclei_vuln_merged_${timestamp}.txt"
    cat "$outputfile" "$nuclei_result_file" | sort -u > "$fallback_output"
    final_input="$fallback_output"
  else
    final_input="$outputfile"
  fi
fi

echo
echo "[→] Validasi akhir menggunakan Curl dan Grep..."
"$script_dir/validate_crlf.sh" "$final_input" "$session_id"
