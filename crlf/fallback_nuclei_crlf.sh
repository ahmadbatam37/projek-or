#!/bin/bash
loxs_result_file="$1"         # Hasil URL dari Loxs
with_param_file="$2"          # crlf_output_with_param.txt
without_param_file="$3"       # crlf_output_without_param.txt
root_only_file="$4"           # crlf_output_root_only.txt
session_id="$5"

fallback_dir="$HOME/Documents/projek-or/crlf/fallback_${session_id}"
mkdir -p "$fallback_dir"

fallback_input="$fallback_dir/fallback_input_nuclei.txt"
nuclei_output="$fallback_dir/nuclei_crlf.txt"

# Normalisasi hasil Loxs → hapus nilai param dan payload jika ada
tmp_loxs_clean="$fallback_dir/loxs_clean.txt"
sed -E 's|://(www\.)?([^/]+).*|://\1\2|' "$loxs_result_file" \
  | sed 's|/$||' \
  | sort -u > "$tmp_loxs_clean"

# Bandingkan semua jenis URL hasil crlf_gather.sh
comm -23 <(sed 's/=[^&]*/=/' "$with_param_file" | sort -u) "$tmp_loxs_clean" > "$fallback_dir/remaining_with_param.txt"
comm -23 <(sort -u "$without_param_file") "$tmp_loxs_clean" > "$fallback_dir/remaining_without_param.txt"
comm -23 <(sort -u "$root_only_file") "$tmp_loxs_clean" > "$fallback_dir/remaining_root_only.txt"

# Gabungkan semua URL yang belum diproses oleh Loxs
cat "$fallback_dir"/remaining_*.txt | sort -u > "$fallback_dir/remaining_all.txt"
tmp_remaining="$fallback_dir/remaining_all.txt"

# Hentikan jika tidak ada yang tersisa
if [[ ! -s "$tmp_remaining" ]]; then
    echo "✅ Semua parameter sudah diproses oleh Loxs. Tidak ada sisa untuk Nuclei."
    exit 0
fi

sort -u "$tmp_remaining" > "$fallback_dir/final_targets.txt"
fallback_input="$fallback_dir/final_targets.txt"

# Jalankan nuclei dengan tag CRLF
echo "[→] Menjalankan scan Nuclei untuk CRLF..."
nuclei -list "$fallback_dir/final_targets.txt" -t ~/nt/nuclei-templates/cRlf.yaml -o "$nuclei_output"
grep -oP 'https?://[^\s]+' "$nuclei_output" > "${nuclei_output}.tmp" && mv "${nuclei_output}.tmp" "$nuclei_output"

# Ringkasan
if [[ -s "$nuclei_output" ]]; then
    echo "[✓] Hasil fallback Nuclei disimpan di:"
    echo "    $nuclei_output"
else
    echo "⚠ Nuclei tidak menemukan kerentanan CRLF."
fi
