#!/bin/bash

# === Input arguments ===
loxs_result="$1"          # File hasil Loxs: vuln_urls_*.txt
original_url_list="$2"    # File hasil or_gather: open_redirect_output.txt
session_id="$3"
export OR_SESSION_ID="$session_id"

# === Validasi input ===
if [[ ! -f "$loxs_result" || ! -f "$original_url_list" ]]; then
  echo "⚠ Gunakan: $0 <hasil_loxs> <open_redirect_output>"
  exit 1
fi

# === Konfigurasi Xray dan direktori output ===
xray_bin="$HOME/Music/xray_linux_amd64"
project_dir="$HOME/Documents/projek-or/open_redirect"
xray_output_dir="$project_dir/fallback_${session_id}"
mkdir -p "$xray_output_dir"
timestamp="$(date +'%Y%m%d-%H%M%S')_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
xray_raw_log="$xray_output_dir/xray_rawlog.txt"
xray_vuln_file="$xray_output_dir/xray_redirect.txt"
tmp_loxs_clean="$xray_output_dir/loxs_param_clean.txt"
tmp_remaining="$xray_output_dir/xray_remaining.txt"

if [[ ! -x "$xray_bin" ]]; then
  echo "❌ File Xray tidak ditemukan atau tidak bisa dieksekusi: $xray_bin"
  exit 1
fi

mkdir -p "$xray_output_dir"

echo "[•] Normalisasi hasil Loxs (hapus nilai parameter)..."
sed 's/=[^&]*/=/' "$loxs_result" | sort -u >  "$tmp_loxs_clean"

echo "[•] Bandingkan dengan hasil or_gather..."
comm -23 <(sort -u "$original_url_list") "$tmp_loxs_clean" > "$tmp_remaining"

if [[ ! -s "$tmp_remaining" ]]; then
  echo "✅ Semua parameter sudah diproses oleh Loxs. Tidak ada sisa untuk Xray."
  exit 0
fi

echo "[→] Menjalankan Xray pada sisa URL..."

while IFS= read -r base_url; do
  [[ -z "$base_url" ]] && continue
  if [[ "$base_url" =~ =[[:space:]]*$ ]]; then
   scan_url="${base_url}https://bing.com"
  else
   scan_url="$base_url"
  fi

  echo "[~] Xray scanning: $scan_url"
  echo -e "\n----- [XRAY OUTPUT for $scan_url] -----"
  (
    cd "$HOME/Music" || exit 1
    ./xray_linux_amd64 webscan --plugins redirect --url "$scan_url" | tee -a "$xray_raw_log"
  )
  echo "----- [END XRAY OUTPUT] -----"

  if grep -A5 -i "\[Vuln: redirect\]" "$xray_raw_log" | grep -q "$base_url"; then
    matched_url=$(grep -A5 -i "\[Vuln: redirect\]" "$xray_raw_log" \
      | grep -Eo 'https?://[^"]+' \
      | grep "$base_url" | head -n1)
    if [[ -n "$matched_url" ]]; then
      echo "$base_url" >> "$xray_vuln_file"
      echo "[✓] Rentan (Xray): $matched_url"
    fi
  else
    echo "[x] Tidak rentan (Xray)"
  fi
done < "$tmp_remaining"

echo
if [[ -s "$xray_vuln_file" ]]; then
  echo "[✓] Xray berhasil mendeteksi URL rentan:"
  cat "$xray_vuln_file"
else
  echo "⚠ Tidak ada URL rentan ditemukan oleh Xray."
fi
