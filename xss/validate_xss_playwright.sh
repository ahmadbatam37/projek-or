#!/bin/bash
# Pindah ke direktori skrip agar output disimpan di lokasi yang benar
script_dir="$(dirname "$(realpath "$0")")"
cd "$script_dir" || exit 1

input_file="$1"
session_id="$2"
export XSS_SESSION_ID="$session_id"

if [[ ! -f "$input_file" ]]; then
  echo "❌ File input tidak ditemukan: $input_file"
  echo "Gunakan: $0 <file_input> <session_id>"
  exit 1
fi

if [[ -z "$session_id" ]]; then
  echo "❌ Session ID tidak diberikan."
  echo "Gunakan: $0 <file_input> <session_id>"
  exit 1
fi

# Buat nama folder dan file output
timestamp="$(date +"%Y%m%d-%H%M%S")_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
output_dir="validate_xss_${timestamp}"
mkdir -p "$output_dir"

validated_output="$output_dir/valid_xss_verified_${timestamp}.txt"
log_output="$output_dir/validation_log_${timestamp}.log"
summary_file="$output_dir/summary.txt"
: > "$summary_file"  # Kosongkan file summary

# Bersihkan input file
temp_input="$output_dir/input_clean.txt"
cp "$input_file" "$temp_input"
dos2unix "$temp_input" 2>/dev/null

total_checked=0
valid_count=0

echo "[i] Validasi XSS menggunakan Playwright"
echo "[i] Input  : $input_file"
echo "[i] Output : $validated_output"
echo

while IFS= read -r url; do
  [[ -z "$url" ]] && continue
  ((total_checked++))
  echo "[>] $url" | tee -a "$summary_file"

  result=$(node validate_xssbaru.js "$url" 2>&1)

  if echo "$result" | grep -q "\[✓\] Alert triggered"; then
    echo "[✓] VALID XSS: Alert triggered" | tee -a "$summary_file"
    echo "$url" >> "$validated_output"
    ((valid_count++))
  else
    echo "[x] TIDAK valid: Alert tidak triggered" | tee -a "$summary_file"
  fi

  # Tambahkan baris kosong untuk jarak
  echo "" | tee -a "$summary_file"

  echo -e "=== $url ===\n$result\n" >> "$log_output"
  echo
done < "$temp_input"

# Ringkasan akhir
echo "───────────────"
if [[ $total_checked -eq 0 ]]; then
  echo "⚠ Tidak ada URL yang diproses."
elif [[ $valid_count -eq $total_checked ]]; then
  echo "✅ Semua URL valid ($valid_count/$total_checked)"
else
  echo "⚠ $valid_count dari $total_checked URL valid"
fi

echo
clear
echo "──────────── RINGKASAN VALIDASI XSS ────────────"
echo "Total URL diuji        : $total_checked"
echo "Terbukti rentan XSS    : $valid_count"
echo
cat "$summary_file"

echo
if [[ -s "$validated_output" ]]; then
  echo "[✓] Semua hasil validasi disimpan di folder: $output_dir"
  echo "[📄] File hasil valid: $(realpath "$validated_output")"
  echo "[📄] Log proses validasi: $log_output"

  echo
  echo "────────────────────────────────────"
  echo "🔍 Menampilkan rekomendasi mitigasi untuk Cross-Site Scripting (XSS):"
  source /home/ahmad/Documents/projek-or/common_function.sh
  get_recommendation "Cross-Site Scripting (XSS)"
else
  echo "⚠ Tidak ada URL XSS valid ditemukan oleh Playwright."
fi

# Hitung durasi proses otomatis dari awal
timer_file="/tmp/.xss_timer_${session_id}.tmp"
if [[ -f "$timer_file" ]]; then
    start_time=$(cat "$timer_file")
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    minutes=$((duration / 60))
    seconds=$((duration % 60))

    echo
    echo "⏱ Total waktu uji penetrasi XSS: ${minutes} menit ${seconds} detik"
    rm -f "$timer_file"
fi