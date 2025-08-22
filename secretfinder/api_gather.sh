#!/bin/bash
session_id="$(date +%Y%m%d%H%M%S)_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
export APILEAK_SESSION_ID="$session_id"


subdomain="$1"
if [[ -z "$subdomain" ]]; then
while true; do
    read -p "[?] Masukkan subdomain (contoh: testphp.vulnweb.com): " subdomain
    

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

echo "$(date +%s)" > "/tmp/.apileak_timer_${session_id}.tmp"

timestamp="$(date +"%Y%m%d-%H%M%S")_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
basedir="$HOME/Documents/projek-or/secretfinder"
output_dir="$basedir/output_${subdomain}-${timestamp}"
mkdir -p "$output_dir"

# File untuk ringkasan
summary_file="$output_dir/summary.txt"
: > "$summary_file"

# Variabel untuk menghitung hasil
js_count=0
api_leak_count=0
xray_vuln_count=0
tech_count=0
exposure_count=0
reverseip_count=0

api_leaks="$output_dir/api_leaks_result.txt"
xray_url_output="$output_dir/fallback_xray_dirscan/xray_dirscan_urls.txt"
nuclei_tech_output="$output_dir/nuclei_tech_result.txt"
nuclei_exposure_output="$output_dir/nuclei_exposure_urls.txt"
reverseip_output="$output_dir/reverseip_result.txt"
jslist="$output_dir/js_list.txt"

# Inisialisasi file kosong
touch "$api_leaks"

KATANA_TIMEOUT="3m"
echo "[i] Memulai pengumpulan data API dan Secret untuk: $subdomain"
echo "[i] Output : $output_dir"
echo


KATANA_TIMEOUT="3m"
echo "[•] Menyiapkan input URL untuk Katana..."
input_list="$output_dir/input_url.txt"
echo "http://$subdomain" > "$input_list"
echo "https://$subdomain" >> "$input_list"

# ===================== FILTER URL AKTIF MENGGUNAKAN HTTPX =====================
echo "[•] Menyaring URL aktif menggunakan httpx..."

active_list="$output_dir/active_urls.txt"
/home/ahmad/go/bin/httpx -l "$input_list" -silent -mc 200,301,302,307,308 -t 50 > "$active_list"

if [[ ! -s "$active_list" ]]; then
    echo "❌ Tidak ada URL aktif yang ditemukan oleh httpx."
    echo "⚠ Menghentikan proses karena tidak ada target yang responsif."
    exit 1
fi

echo "[✓] URL aktif disimpan di: $active_list"

active_tmp="$output_dir/katana_js.tmp"

echo "[•] Menjalankan Katana crawling (HTTP & HTTPS)..."
timeout "$KATANA_TIMEOUT" katana -list "$active_list" -d 3 \
  | grep '\.js' | grep -E "^https?://(www\.)?$subdomain(\b|/)" \
  | sort -u > "$active_tmp"

katana_exit=$?
if [[ $katana_exit -eq 124 || $katana_exit -eq 137 ]]; then
  echo "⚠ Katana dihentikan karena melebihi waktu $KATANA_TIMEOUT."
fi


cp "$active_tmp" "$jslist"
echo "[✓] Daftar file JS disimpan ke: $jslist"

if [[ ! -s "$jslist" ]]; then
    echo "⚠ Tidak ditemukan file JS dari hasil crawling."
    echo "ℹ Tidak perlu menjalankan SecretFinder."
    touch "$api_leaks"
else    

# Jalankan SecretFinder untuk tiap JS
echo "[•] Menjalankan SecretFinder untuk mendeteksi kebocoran API key..."


> "$api_leaks"

while read -r js_url; do
    python3 SecretFinder.py -i "$js_url" -o cli 2>/dev/null | \
    awk -v url="$js_url" '
        /->/ {
            type=""; value="";
            for(i=1;i<=NF-2;i++) type = type $i " ";
            value = $(NF);
            gsub(/[ \t]+$/, "", type);
            print "[URL] " url "\n[TYPE] " type "\n[VALUE] " value "\n-----------------------------"
        }
    '
done < "$jslist" >> "$api_leaks"

echo
echo "────────────────────────────────────"
echo "[✓] Semua URL JS disimpan di     : $jslist"
echo "[✓] Hasil deteksi API leak di    : $api_leaks"

fi
# === Jalankan Xray dirscan untuk http & https ===
echo "[•] Menjalankan Xray untuk deteksi direktori tersembunyi (HTTP & HTTPS)..."

xray_bin="$HOME/Music/xray_linux_amd64"
xray_output_dir="$output_dir/fallback_xray_dirscan"
mkdir -p "$xray_output_dir"

xray_rawlog="$xray_output_dir/xray_rawlog.txt"
xray_url_output="$xray_output_dir/xray_dirscan_urls.txt"

if [[ ! -x "$xray_bin" ]]; then
  echo "❌ File Xray tidak ditemukan atau tidak bisa dieksekusi: $xray_bin"
else
  while read -r full_url; do
    echo "[~] Xray scanning: $full_url"
    echo -e "\n----- [XRAY OUTPUT for $full_url] -----"
    (
      cd "$HOME/Music" || exit 1
      ./xray_linux_amd64 webscan --plugins dirscan --url "$full_url"
    ) | tee -a "$xray_rawlog"
    echo "----- [END XRAY OUTPUT] -----"
  done < "$active_list"

  grep -A5 "\[Vuln: dirscan\]" "$xray_rawlog" | grep 'Target' | awk -F'"' '{print $2}' | sort -u > "$xray_url_output"

  echo
  if [[ -s "$xray_url_output" ]]; then
    echo "[✓] URL direktori rentan ditemukan oleh Xray:"
    cat "$xray_url_output"
    echo "[✓] Hasil disimpan di                 : $xray_url_output"
  else
    echo "⚠ Tidak ada URL rentan ditemukan oleh Xray."
  fi
fi

# ===================== NUCLEI: TECH =====================
echo "[•] Menjalankan nuclei -tags tech dengan -list..."
nuclei -list "$active_list" -tags tech -o "$nuclei_tech_output" 2>/dev/null
echo "[✓] Hasil deteksi teknologi disimpan di: $nuclei_tech_output"

if [[ -s "$nuclei_tech_output" ]]; then
  echo "[✓] Hasil deteksi teknologi disimpan di: $nuclei_tech_output"
else
  echo "⚠ Tidak ada teknologi yang terdeteksi oleh Nuclei."
fi

# ===================== NUCLEI: EXPOSURES =====================
echo "[•] Menjalankan nuclei -t exposures dengan -list..."
nuclei -list "$active_list" -t "$HOME/nuclei-templates/http/exposures" -t "$HOME/nt/nuclei-templates/credentials-disclosure-all.yaml" -o "$nuclei_exposure_output" 2>/dev/null
echo "[✓] URL yang terdeteksi oleh template exposures disimpan di: $nuclei_exposure_output"

if [[ -s "$nuclei_exposure_output" ]]; then
  echo "[✓] URL yang terdeteksi oleh template exposures disimpan di: $nuclei_exposure_output"
else
  echo "⚠ Tidak ada hasil exposures ditemukan oleh Nuclei."
fi


# ===================== VIEWDNS REVERSE IP =====================
echo "[•] Menjalankan reverse IP lookup dengan viewdns_tool.py..."
viewdns_bin="$HOME/Documents/projek-or/secretfinder/viewdns_tool.py"
> "$reverseip_output"

if [[ -f "$viewdns_bin" ]]; then
  python3 "$viewdns_bin" --reverseip "$subdomain" | tee "$reverseip_output"
  echo "[✓] Hasil reverse IP disimpan di: $reverseip_output"
else
  echo "⚠ viewdns_tool.py tidak ditemukan di $viewdns_bin"
fi

# Setelah proses SecretFinder
if [[ -s "$api_leaks" ]]; then
    api_leak_count=$(grep -c "\[URL\]" "$api_leaks")
    echo "[✓] Ditemukan $api_leak_count kebocoran API/Secret" | tee -a "$summary_file"
    echo "    Detail kebocoran:" | tee -a "$summary_file"
    grep -A2 "\[TYPE\]" "$api_leaks" | head -10 | sed 's/^/    /' | tee -a "$summary_file"
    if [[ $api_leak_count -gt 5 ]]; then
        echo "    ... dan $((api_leak_count - 5)) lainnya" | tee -a "$summary_file"
    fi
else
    echo "[x] Tidak ditemukan kebocoran API/Secret" | tee -a "$summary_file"
fi
echo "" | tee -a "$summary_file"

# Setelah proses Xray
if [[ -s "$xray_url_output" ]]; then
    xray_vuln_count=$(wc -l < "$xray_url_output")
    echo "[✓] Ditemukan $xray_vuln_count direktori tersembunyi" | tee -a "$summary_file"
    echo "    Detail direktori:" | tee -a "$summary_file"
    head -10 "$xray_url_output" | sed 's/^/    /' | tee -a "$summary_file"
    if [[ $xray_vuln_count -gt 10 ]]; then
        echo "    ... dan $((xray_vuln_count - 10)) lainnya" | tee -a "$summary_file"
    fi
else
    echo "[x] Tidak ditemukan direktori tersembunyi" | tee -a "$summary_file"
fi
echo "" | tee -a "$summary_file"

# Setelah proses Nuclei Tech
if [[ -s "$nuclei_tech_output" ]]; then
    tech_count=$(wc -l < "$nuclei_tech_output")
    echo "[✓] Ditemukan $tech_count teknologi" | tee -a "$summary_file"
    echo "    Detail teknologi:" | tee -a "$summary_file"
    # PERBAIKAN DI SINI: Gunakan awk yang lebih cerdas untuk menyertakan versi
    awk -F'[][]' '{ gsub(/"/,"", $8); if ($8 != "") {print $2 " (" $8 ")" } else { print $2 }}' "$nuclei_tech_output" | head -10 | sed 's/^/    /' | tee -a "$summary_file"
    if [[ $tech_count -gt 10 ]]; then
        echo "    ... dan $((tech_count - 10)) lainnya" | tee -a "$summary_file"
    fi
else
    echo "[x] Tidak ditemukan teknologi" | tee -a "$summary_file"
fi
echo "" | tee -a "$summary_file"

# Setelah proses Nuclei Exposure
if [[ -s "$nuclei_exposure_output" ]]; then
    exposure_count=$(wc -l < "$nuclei_exposure_output")
    echo "[✓] Ditemukan $exposure_count exposure" | tee -a "$summary_file"
    echo "    Detail exposure:" | tee -a "$summary_file"
    # Ambil URL dari kolom terakhir (setelah spasi terakhir)
    awk '{print $NF}' "$nuclei_exposure_output" | head -10 | sed 's/^/    /' | tee -a "$summary_file"
    if [[ $exposure_count -gt 10 ]]; then
        echo "    ... dan $((exposure_count - 10)) lainnya" | tee -a "$summary_file"
    fi
else
    echo "[x] Tidak ditemukan exposure" | tee -a "$summary_file"
fi
echo "" | tee -a "$summary_file"

# Perbaiki bagian ViewDNS (sekitar baris 250-270)
# Setelah proses ViewDNS
if [[ -s "$reverseip_output" ]]; then
    # Hitung berdasarkan baris yang mengandung domain (baris dengan format "- domain.com")
    reverseip_count=$(grep -c "^- " "$reverseip_output" 2>/dev/null || echo "0")
    
    if [[ $reverseip_count -gt 0 ]]; then
        echo "[✓] Ditemukan $reverseip_count hasil reverse IP" | tee -a "$summary_file"
        echo "    Detail reverse IP:" | tee -a "$summary_file"
        # Ambil domain dari baris yang dimulai dengan "- "
        grep "^- " "$reverseip_output" | head -10 | sed 's/^/    /' | tee -a "$summary_file"
        if [[ $reverseip_count -gt 10 ]]; then
            echo "    ... dan $((reverseip_count - 10)) lainnya" | tee -a "$summary_file"
        fi
    else
        echo "[x] Tidak ditemukan hasil reverse IP" | tee -a "$summary_file"
    fi
else
    echo "[x] Tidak ditemukan hasil reverse IP" | tee -a "$summary_file"
fi
echo "" | tee -a "$summary_file"

# Hitung total file JS dan tampilkan detail
if [[ -s "$jslist" ]]; then
    js_count=$(wc -l < "$jslist")
    echo "[✓] Ditemukan $js_count file JavaScript" | tee -a "$summary_file"
    echo "    Detail file JS:" | tee -a "$summary_file"
    head -5 "$jslist" | sed 's/^/    /' | tee -a "$summary_file"
    if [[ $js_count -gt 5 ]]; then
        echo "    ... dan $((js_count - 5)) lainnya" | tee -a "$summary_file"
    fi
else
    echo "[x] Tidak ditemukan file JavaScript" | tee -a "$summary_file"
fi
echo "" | tee -a "$summary_file"

# Timer selesai
end_time=$(date +%s)
start_time=$(cat "/tmp/.apileak_timer_${session_id}.tmp")
duration=$((end_time - start_time))
minutes=$((duration / 60))
seconds=$((duration % 60))

# Ringkasan akhir
echo
clear
echo "──────────── RINGKASAN PENGUMPULAN API/SECRET ────────────"
echo "Target subdomain       : $subdomain"
echo "File JavaScript        : $js_count"
echo "API/Secret leaks       : $api_leak_count"
echo "Direktori tersembunyi  : $xray_vuln_count"
echo "Teknologi terdeteksi   : $tech_count"
echo "Exposure ditemukan     : $exposure_count"
echo "Reverse IP results     : $reverseip_count"
echo
cat "$summary_file"

echo
echo "[✓] Semua hasil disimpan di folder: $output_dir"
echo "[📄] File JavaScript: $jslist"
echo "[📄] API leaks: $api_leaks"
echo "[📄] Xray results: $xray_url_output"
echo "[📄] Nuclei tech: $nuclei_tech_output"
echo "[📄] Nuclei exposure: $nuclei_exposure_output"
echo "[📄] Reverse IP: $reverseip_output"

echo
echo "⏱ Total waktu pengumpulan data: ${minutes} menit ${seconds} detik"

# Cleanup timer
rm -f "/tmp/.apileak_timer_${session_id}.tmp"

