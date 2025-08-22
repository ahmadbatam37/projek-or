#!/bin/bash
# Pindah ke direktori skrip agar output disimpan di lokasi yang benar
script_dir="$(dirname "$(realpath "$0")")"
cd "$script_dir" || exit 1

input_file="$1"
session_id="$2"
export LFI_SESSION_ID="$session_id"

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
output_dir="validate_lfi_${timestamp}"
mkdir -p "$output_dir"

validated_output="$output_dir/valid_lfi_verified_${timestamp}.txt"
log_output="$output_dir/validation_log_${timestamp}.log"
summary_file="$output_dir/summary.txt"
: > "$summary_file"  # Kosongkan file summary

# Bersihkan input file
temp_input="$output_dir/input_clean.txt"
cp "$input_file" "$temp_input"
dos2unix "$temp_input" 2>/dev/null

total_checked=0
valid_count=0

echo "[i] Validasi LFI menggunakan curl dan grep (/etc/passwd)"
echo "[i] Input  : $input_file"
echo "[i] Output : $validated_output"
echo

while IFS= read -r url; do
  [[ -z "$url" ]] && continue
  ((total_checked++))
  echo "[>] $url" | tee -a "$summary_file"

  # Ambil response dengan curl (user-agent browser & follow redirect)
  response=$(curl -skL -A "Mozilla/5.0" "$url" --max-time 10 2>/dev/null)

  # Validasi isi /etc/passwd (indikator LFI klasik)
  if echo "$response" | grep -qE "root:.*:0:0:"; then
    echo "[✓] VALID LFI: Ditemukan /etc/passwd" | tee -a "$summary_file"
    echo "$url" >> "$validated_output"
    ((valid_count++))
  else
    echo "[x] TIDAK valid: Tidak ditemukan /etc/passwd" | tee -a "$summary_file"
  fi

  echo -e "=== $url ===\n$response\n" >> "$log_output"
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
echo "──────────── RINGKASAN VALIDASI LFI ────────────"
echo "Total URL diuji        : $total_checked"
echo "Terbukti rentan LFI    : $valid_count"
echo
cat "$summary_file"

echo
if [[ -s "$validated_output" ]]; then
  echo "[✓] Semua hasil validasi disimpan di folder: $output_dir"
  echo "[📄] File hasil valid: $(realpath "$validated_output")"
  echo "[📄] Log proses validasi: $log_output"

  # Tampilkan rekomendasi mitigasi untuk LFI
  echo
  echo "────────────────────────────────────"
  echo "🔍 Menampilkan rekomendasi mitigasi untuk Local File Inclusion (LFI):"
  source /home/ahmad/Documents/projek-or/common_function.sh
  get_recommendation "Local File Inclusion (LFI)"
else
  echo "⚠ Tidak ada URL valid ditemukan oleh curl."
fi

# Hitung durasi proses otomatis dari awal
timer_file="/tmp/.lfi_timer_${session_id}.tmp"
if [[ -f "$timer_file" ]]; then
    start_time=$(cat "$timer_file")
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    minutes=$((duration / 60))
    seconds=$((duration % 60))

    echo
    echo "⏱ Total waktu uji penetrasi LFI: ${minutes} menit ${seconds} detik"
    rm -f "$timer_file"
fi