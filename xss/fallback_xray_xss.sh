#!/bin/bash

# === Input arguments ===
loxs_result="$1"          # File hasil Loxs: vuln_urls_*.txt
original_url_list="$2"    # File hasil or_gather: xss_output.txt
session_id="$3"
export XSS_SESSION_ID="$session_id"

# === Validasi input ===
if [[ ! -f "$loxs_result" || ! -f "$original_url_list" ]]; then
  echo "⚠ Gunakan: $0 <hasil_loxs> <open_redirect_output>"
  exit 1
fi

# === Konfigurasi Xray dan direktori output ===
xray_bin="$HOME/Music/xray_linux_amd64"
project_dir="$HOME/Documents/projek-or/xss"
xray_output_dir="$project_dir/fallback_${session_id}"
mkdir -p "$xray_output_dir"
timestamp="$(date +'%Y%m%d-%H%M%S')_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)"
xray_raw_log="$xray_output_dir/xray_rawlog.txt"
xray_vuln_file="$xray_output_dir/xray_xss.txt"
tmp_loxs_clean="$xray_output_dir/loxs_param_clean.txt"
tmp_remaining="$xray_output_dir/xray_remaining.txt"

if [[ ! -x "$xray_bin" ]]; then
  echo "❌ File Xray tidak ditemukan atau tidak bisa dieksekusi: $xray_bin"
  exit 1
fi

mkdir -p "$xray_output_dir"

echo "[•] Normalisasi hasil Loxs (hapus nilai parameter)..."
sed 's/=[^&]*/=/' "$loxs_result" | sort -u >  "$tmp_loxs_clean"

echo "[•] Bandingkan dengan hasil xss_gather..."
comm -23 <(sort -u "$original_url_list") "$tmp_loxs_clean" > "$tmp_remaining"

if [[ ! -s "$tmp_remaining" ]]; then
  echo "✅ Semua parameter sudah diproses oleh Loxs. Tidak ada sisa untuk Xray."
  exit 0
fi

echo "[→] Menjalankan Xray pada sisa URL..."

while IFS= read -r base_url; do
  [[ -z "$base_url" ]] && continue
  echo "[~] Xray scanning: $base_url"
  echo -e "\n----- [XRAY OUTPUT for $base_url] -----"
  (
    cd "$HOME/Music" || exit 1
    ./xray_linux_amd64 webscan --plugins xss --url "$base_url" | tee -a "$xray_raw_log"
  )
  echo "----- [END XRAY OUTPUT] -----"

  if grep -A5 -i "\[Vuln: xss\]" "$xray_raw_log" | grep -q "$base_url"; then
  payload=$(grep -A5 -i "\[Vuln: xss\]" "$xray_raw_log" | awk -F'"' '/Payload/ {print $2; exit}')
  param_key=$(grep -A5 -i "\[Vuln: xss\]" "$xray_raw_log" | awk -F'"' '/ParamKey/ {print $2; exit}')
  target=$(grep -A5 -i "\[Vuln: xss\]" "$xray_raw_log" | awk -F'"' '/Target/ {print $2; exit}')

  if [[ -n "$target" && -n "$param_key" && -n "$payload" ]]; then
    vuln_url="${target}${payload}"
    echo "$vuln_url" >> "$xray_vuln_file"
    echo "[✓] Rentan (Xray): $vuln_url"
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
