#!/bin/bash
# Pindah ke direktori skrip agar output disimpan di lokasi yang benar
script_dir="$(dirname "$(realpath "$0")")"
cd "$script_dir" || exit 1

input="$1"
timestamp="$(date +"%Y%m%d-%H%M%S")_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
output_dir="validate_${timestamp}"
mkdir -p "$output_dir"
summary_file="$output_dir/summary.txt"
: > "$summary_file"  # Kosongkan file summary

output="$output_dir/valid_open_redirect_verified_${timestamp}.txt"
log_output="$output_dir/validation_log_${timestamp}.log"

echo "[i] Validasi via header langsung (HTTP/1.1 + User-Agent browser)"
echo "[i] Input  : $input"
echo "[i] Output : $output"
echo

# ✅ Bersihkan karakter Windows-style (CRLF)
temp_input="$output_dir/input_clean.txt"
cp "$input" "$temp_input"
dos2unix "$temp_input" 2>/dev/null

# Inisialisasi penghitung
total=0
valid=0

while IFS= read -r url; do
    [[ -z "$url" ]] && continue  # skip baris kosong
    ((total++))
    echo "[>] $url" | tee -a "$summary_file" | tee -a "$log_output"

    tmpfile=$(mktemp)

    # Jalankan curl dengan timeout dan simpan header
    curl -s --http1.1 --max-time 20 -D "$tmpfile" -o /dev/null \
        -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36" \
        "$url"
    curl_exit=$?

    if [[ $curl_exit -ne 0 ]]; then
        echo "[x] Curl error (exit code $curl_exit), mungkin timeout atau koneksi gagal" | tee -a "$summary_file" | tee -a "$log_output"
        cp "$tmpfile" "$output_dir/debug_curl_error_$(basename "$url" | tr -cd '[:alnum:]').txt"
        rm -f "$tmpfile"
        echo
        continue
    fi

    code=$(sed -n '/^HTTP/s/[^ ]* \([0-9]*\).*/\1/p' "$tmpfile" | head -n1)
    location=$(sed -n 's/^[Ll]ocation:[[:space:]]*//p' "$tmpfile" | tr -d '\r')

    if [[ -z "$code" ]]; then
        echo "[x] Tidak ada status code ditemukan" | tee -a "$summary_file" | tee -a"$log_output"
        cp "$tmpfile" "$output_dir/debug_no_code_$(basename "$url" | tr -cd '[:alnum:]').txt"
        rm -f "$tmpfile"
        echo
        continue
    fi
    # Ambil host dari URL asli
    host=$(echo "$url" | awk -F/ '{print $3}')

    # Cek apakah redirect ke domain eksternal (bukan domain asal)
    if [[ "$code" =~ ^3[0-9][0-9]$ && "$location" =~ ([/:.])?[a-zA-Z0-9.-]+\.[a-z]{2,} ]]; then
        echo "[✓] $code → $location" | tee -a "$summary_file" | tee -a "$log_output"
        echo "$url" >> "$output"
        ((valid++))
    else
        echo "[x] $code → $location" | tee -a "$summary_file" | tee -a "$log_output"
        if [[ -z "$location" ]]; then
            cp "$tmpfile" "$output_dir/debug_no_location_$(basename "$url" | tr -cd '[:alnum:]').txt"
        fi
    fi

    rm -f "$tmpfile"
    echo
done < "$temp_input"

# Ringkasan akhir
echo "───────────────"
if [[ $total -eq 0 ]]; then
    echo "⚠  Tidak ada URL yang diproses."
elif [[ $valid -eq $total ]]; then
    echo "✅ Semua URL valid ($valid/$total)"
else
    echo "⚠  $valid dari $total URL valid"
fi

echo
clear
echo "──────────── RINGKASAN VALIDASI OPEN REDIRECT ────────────"
echo "Total URL diuji        : $total"
echo "Terbukti redirect      : $valid"
echo
cat "$summary_file"



# Tampilkan rekomendasi mitigasi jika ada URL valid
echo
if [[ -s "$output" ]]; then
    echo "[✓] Semua hasil validasi disimpan di folder: $output_dir"
    echo "[📄] File hasil valid: $(realpath "$output")"
    echo "[📄] Log proses validasi: $log_output"
    echo
    echo "────────────────────────────────────"
    echo "🔍 Menampilkan rekomendasi mitigasi untuk Open Redirect:"
    source /home/ahmad/Documents/projek-or/common_function.sh
    get_recommendation "Open Redirect"
else
    echo "⚠ Tidak ada URL valid ditemukan oleh curl."
fi

# Hitung durasi proses otomatis dari awal
if [[ -n "$OR_SESSION_ID" && -f "/tmp/.or_timer_${OR_SESSION_ID}.tmp" ]]; then
    start_time=$(cat "/tmp/.or_timer_${OR_SESSION_ID}.tmp")
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    minutes=$((duration / 60))
    seconds=$((duration % 60))

    echo
    echo "⏱ Total waktu uji penetrasi Open Redirect: ${minutes} menit ${seconds} detik"
    rm -f "/tmp/.or_timer_${OR_SESSION_ID}.tmp"
fi
