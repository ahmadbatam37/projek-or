#!/bin/bash
# Pindah ke direktori skrip agar output disimpan di lokasi yang benar
script_dir="$(dirname "$(realpath "$0")")"
cd "$script_dir" || exit 1

input="$1"
if [[ ! -f "$input" ]]; then
    echo "⚠ File tidak ditemukan: $input"
    echo "🔧 Gunakan: $0 <file_url>"
    exit 1
fi

# Gunakan session ID dari environment jika tersedia
session_id="${SQLI_SESSION_ID:-sqli_$(date +'%Y%m%d-%H%M%S')_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)}"
timestamp="$session_id"
output_dir="validate_sqli_${timestamp}"

# Jangan timpa timer jika sudah ada
timer_file="/tmp/.sqli_timer_${session_id}.tmp"
if [[ ! -f "$timer_file" ]]; then
    echo "$(date +%s)" > "$timer_file"
fi

mkdir -p "$output_dir"
summary_file="$output_dir/summary.txt"
: > "$summary_file"  # Kosongkan file
temp_input="$output_dir/input_clean.txt"
cp "$input" "$temp_input"
dos2unix "$temp_input" 2>/dev/null

# Normalisasi URL: ubah semua nilai parameter jadi "1", lalu dedup
uniq_input="$output_dir/unique_input.txt"
sed -E 's/=[^&]*/=1/g' "$temp_input" | sort -u > "$uniq_input"

output="$output_dir/valid_sqli_dumped_${timestamp}.txt"
total=0
valid=0

echo "[i] Validasi SQLi menggunakan sqlmap (dump database)"
echo "[i] Input  : $input"
echo "[i] Output : $output"
echo

while IFS= read -r clean_url; do
    [[ -z "$clean_url" ]] && continue
    ((total++))
    echo "[>] $clean_url" | tee -a "$summary_file"

   # Jalankan sqlmap dan tampilkan output langsung
   tmp_dir="$output_dir/sqlmap_${total}"
   mkdir -p "$tmp_dir"
   sqlmap --batch --output-dir="$tmp_dir" -u "$clean_url" --dbs --level=3 --risk=2 --threads=5 --flush-session | tee "$tmp_dir/sqlmap.log"

   if grep -q "Parameter: " "$tmp_dir/sqlmap.log"; then
    echo "📌 Teknik Injeksi SQLi yang ditemukan pada parameter:" | tee -a "$summary_file"
    awk '/Parameter: /,/Do you want to keep testing the others/ { print }' "$tmp_dir/sqlmap.log" \
    | grep -vE "^\[INFO\]|\[WARNING\]|\[CRITICAL\]|^\[.*ending @|you can find results|do you want to exploit" \
    | sed '/^$/N;/^\n$/D' \
| tee -a "$summary_file"
   fi


   # Validasi dari log sqlmap apakah ditemukan database
   if grep -q "available databases" "$tmp_dir/sqlmap.log"; then
       echo "[✓] Terbukti rentan & berhasil dump DB" | tee -a "$summary_file"
       echo "$clean_url" >> "$output"
       ((valid++))

       echo "📦 Database ditemukan:" | tee -a "$summary_file"
       awk '/available databases/,/\[INFO\]/' "$tmp_dir/sqlmap.log" \
           | grep -E '^\[\*\]' \
           | sed 's/\[\*\] / - /' | tee -a "$summary_file"
   else
       echo "[x] Tidak terbukti rentan / tidak berhasil dump DB" | tee -a "$summary_file"
   fi


    echo
done < "$uniq_input"

# Ringkasan akhir
echo "───────────────"
if [[ $total -eq 0 ]]; then
    echo "⚠ Tidak ada URL yang diproses."
elif [[ $valid -eq $total ]]; then
    echo "✅ Semua URL valid SQLi ($valid/$total)"
else
    echo "⚠ $valid dari $total URL berhasil dump DB"
fi

echo
echo "[✓] Hasil validasi disimpan di folder: $output_dir"
echo "[📄] File valid: $(realpath "$output")"

# Hitung durasi
if [[ -n "$SQLI_SESSION_ID" && -f "/tmp/.sqli_timer_${SQLI_SESSION_ID}.tmp" ]]; then
    start_time=$(cat "/tmp/.sqli_timer_${SQLI_SESSION_ID}.tmp")
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    minutes=$((duration / 60))
    seconds=$((duration % 60))
    echo
    clear
    # Clear terminal dan tampilkan ringkasan

    echo "──────────── RINGKASAN VALIDASI SQLi ────────────"
    echo "Total URL diuji  : $total"
    echo "Terbukti rentan  : $valid"
    echo
    cat "$summary_file"

    echo
    echo "────────────────────────────────────"
    if [[ $valid -gt 0 ]]; then
        echo "🔍 Menampilkan rekomendasi mitigasi untuk SQL Injection:"
        source /home/ahmad/Documents/projek-or/common_function.sh
        get_recommendation "SQL Injection"
    fi

    echo "⏱ Total waktu uji penetrasi SQLi: ${minutes} menit ${seconds} detik"
    rm -f "/tmp/.sqli_timer_${SQLI_SESSION_ID}.tmp"
fi
