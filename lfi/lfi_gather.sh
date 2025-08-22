#!/bin/bash
session_id="$(date +%Y%m%d%H%M%S)_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
export LFI_SESSION_ID="$session_id"


subdomain="$1"
crawling_dir="$2"
if [[ -z "$subdomain" ]]; then
while true; do
    read -p "[?] Masukkan subdomain (contoh: testphp.vulnweb.com): " subdomain
    

    # Validasi format subdomain
    if ! [[ "$subdomain" =~ ^[a-zA-Z0-9.-]+\.[a-z]{2,}$ ]]; then
        echo "❌ Format subdomain tidak valid."
        continue
    fi

    echo "[•] Domain target yang akan diuji adalah: $subdomain"
    read -p "[?] Apakah ingin lanjutkan uji terhadap domain ini? (y=lanjut / n=ganti / q=keluar): " jawab

    case "$jawab" in
        [Yy]) break ;;
        [Qq]) echo "❌ Proses dibatalkan oleh pengguna."; exit 0 ;;
        *) echo "↪ Silakan masukkan domain baru."; continue ;;
    esac
done
else
    # Log bahwa subdomain diterima dari parameter
    echo "[•] Menggunakan subdomain yang diberikan : $subdomain"
fi

echo "$(date +%s)" > "/tmp/.lfi_timer_${session_id}.tmp"

timestamp="$(date +"%Y%m%d-%H%M%S")_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
basedir="$HOME/Documents/projek-or/lfi"
output_dir="$basedir/output_${subdomain}-${timestamp}"
mkdir -p "$output_dir"

if [[ -n "$crawling_dir" && -d "$crawling_dir" ]]; then
    echo "[•] Menggunakan hasil crawling dari: $crawling_dir"
    katana_file="$crawling_dir/katana.txt"
    paramspider_file="$crawling_dir/paramspider_clean.txt"
else
    echo "[•] Tidak ada direktori hasil crawling yang diberikan. Melakukan crawling..."
    KATANA_TIMEOUT="3m"
    # Step 1: Siapkan input_url.txt untuk katana (http + https)
    echo "http://$subdomain" > "$output_dir/input_url.txt"
    echo "https://$subdomain" >> "$output_dir/input_url.txt"

    # Step 2: Jalankan paramspider
    echo "[•] Menjalankan paramspider..."
    paramspider_output="results/$subdomain.txt"
    paramspider_clean="$output_dir/paramspider_clean.txt"

    paramspider -d "$subdomain" > /dev/null

    if [[ -f "$paramspider_output" ]]; then
        cp "$paramspider_output" "$output_dir/paramspider_raw.txt"
        cat "$output_dir/paramspider_raw.txt" | \
        grep -E "^https?://(www\.)?$subdomain(\b|/)" | \
        grep -vE 'http.*http' | \
        sed 's/FUZZ//g' | \
        sort -u > "$paramspider_clean"

        echo "[✓] Paramspider hasil disimpan di: $paramspider_clean"
    else
        echo "⚠ Paramspider tidak menghasilkan file: $paramspider_output"
        touch "$paramspider_clean"
    fi

    # Step 3: Jalankan katana passive
    echo "[•] Katana passive scan..."
    katana -list "$output_dir/input_url.txt" -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro | grep -E "^https?://(www\.)?$subdomain(\b|/)" | grep -vE 'http.*http' > "$output_dir/katana.txt"

    # Step 4: Jalankan katana active
    echo "[•] Katana active scan..."
    echo "[DEBUG] Jumlah baris katana.txt sebelum active scan:"
    wc -l < "$output_dir/katana.txt"

    active_tmp="$output_dir/katana_active.tmp"

    timeout "$KATANA_TIMEOUT" katana -list "$output_dir/input_url.txt" -d 5 -f qurl | uro | grep -E "^https?://(www\.)?$subdomain(\b|/)" | grep -vE 'http.*http'  > "$active_tmp"
    katana_exit=$?

    if [[ $katana_exit -eq 124 || $katana_exit -eq 137 ]]; then
    echo "⚠ Katana dihentikan karena melebihi waktu $KATANA_TIMEOUT."
    fi

    echo "[DEBUG] Jumlah hasil active scan sementara:"
    wc -l < "$active_tmp"

    if [[ -s "$active_tmp" ]]; then
    cat "$active_tmp" | anew "$output_dir/katana.txt" > /dev/null
    fi

    echo "[DEBUG] Jumlah baris katana.txt setelah active scan:"
    wc -l < "$output_dir/katana.txt"

    katana_file="$output_dir/katana.txt"
    paramspider_file="$paramspider_clean"
fi

# Step 5: Gabungkan hasil katana + paramspider
echo "[•] Menggabungkan hasil URL..."
cat "$katana_file" "$paramspider_file" | sort -u > "$output_dir/output.txt"

# Step 6: Filtering endpoint LFI
echo "[•] Filtering URLs for potential LFI endpoints..."
cat "$output_dir/output.txt" | gf lfi | sed 's/=.*/=/' | sort -u > "$output_dir/lfi_output.txt"
echo "[✓] Extracting final filtered URLs to: $output_dir/lfi_output.txt"

# Step 7: Cek apakah hasil lfi kosong
if [[ ! -s "$output_dir/lfi_output.txt" ]]; then
    echo "⚠ Tidak ditemukan endpoint LFI dari hasil crawling."
    echo "ℹ Tidak perlu menjalankan scanner."
    exit 0
fi

# Step 8: Tampilkan ringkasan
echo "────────────────────────────────────"
echo "[✓] Semua URL disimpan di        : $output_dir/output.txt"
echo "[✓] LFI suspected URL di         : $output_dir/lfi_output.txt"

# Step 9: Jalankan scanner otomatis (misal: run_lfi_auto1.sh)
echo
echo "[→] Menjalankan scanner otomatis..."
script_dir="$(dirname "$(realpath "$0")")"
"$script_dir/run_lfi_auto1.sh" "$output_dir/lfi_output.txt" "$session_id"
