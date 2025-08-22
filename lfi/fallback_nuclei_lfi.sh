#!/bin/bash
loxs_result_file="$1"       # Output URL dari Loxs
original_input_file="$2"    # File hasil filter gf lfi
session_id="$3"

fallback_dir="$HOME/Documents/projek-or/lfi/fallback_${session_id}"
mkdir -p "$fallback_dir"

fallback_input="$fallback_dir/fallback_input_nuclei.txt"
nuclei_output="$fallback_dir/nuclei_lfi.txt"
# Normalisasi hasil Loxs → hapus nilai param agar jadi ...?param=
tmp_loxs_clean="$fallback_dir/loxs_clean.txt"
sed 's/=[^&]*/=/' "$loxs_result_file" | sort -u > "$tmp_loxs_clean"

# Filter hanya param= yang belum diproses oleh Loxs
tmp_remaining="$fallback_dir/remaining_param_equals.txt"
comm -23 <(sort -u "$original_input_file") "$tmp_loxs_clean" > "$tmp_remaining"

# Hentikan jika tidak ada yang tersisa
if [[ ! -s "$tmp_remaining" ]]; then
    echo "✅ Semua parameter sudah diproses oleh Loxs. Tidak ada sisa untuk Nuclei."
    exit 0
fi

echo "[•] Menyiapkan variasi input untuk fallback Nuclei..."

# Kosongkan file input awal
> "$fallback_input"

# Hasilkan 3 variasi URL hanya dari param= yang belum diproses Loxs
while read -r url_from_lfi_list; do
    # Gunakan URL asli dari lfi_output.txt tanpa diubah
    original_url="$url_from_lfi_list"

    # Simpan versi ?param (tanpa '=')
    query_param=$(echo "$original_url" | grep -oP '\?[a-zA-Z0-9_]+')
    if [[ -n "$query_param" ]]; then
        clean_param_url=$(echo "$original_url" | sed 's/=\+$//' | sed 's/&\+$//')
        echo "$clean_param_url" >> "$fallback_input"
    fi

    # Simpan versi tanpa query string (hanya path)
    base_path_url=$(echo "$original_url" | cut -d'?' -f1)
    echo "$base_path_url" >> "$fallback_input"

    # Simpan versi root domain (tanpa path)
    root_domain_url=$(echo "$base_path_url" | awk -F/ '{print $1 "//" $3 "/"}')
    echo "$root_domain_url" >> "$fallback_input"
done < "$tmp_remaining"


# Hapus duplikat
sort -u -o "$fallback_input" "$fallback_input"
cp "$fallback_input" "$fallback_dir/final_targets.txt"

# Jalankan nuclei dengan tag LFI
echo "[→] Menjalankan scan Nuclei untuk LFI..."
nuclei -list "$fallback_dir/final_targets.txt" -tags lfi -o "$nuclei_output"
grep -oP 'https?://[^\s]+' "$nuclei_output" > "${nuclei_output}.tmp" && mv "${nuclei_output}.tmp" "$nuclei_output"
# Ringkasan
if [[ -s "$nuclei_output" ]]; then
    echo "[✓] Hasil fallback Nuclei disimpan di:"
    echo "    $nuclei_output"
else
    echo "⚠ Nuclei tidak menemukan kerentanan LFI."
fi
