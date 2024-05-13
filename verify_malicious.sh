#!/bin/bash

# Verifică dacă numărul de argumente este corect
if [ $# -ne 1 ]; then
    exit 1
fi

file=$1

# Verifică drepturile de acces ale fișierului
if [ "$(stat -c "%a" "$file")" -eq 0 ]; then
    echo "$file MALICIOUS"
    exit 0
fi

# Numărul minim de linii, cuvinte și caractere
min_lines=3
min_words=1000
min_chars=2000

# Verifică dacă fișierul există
if [ ! -f "$file" ]; then
    echo "File not found: $file"
    exit 1
fi

# Redirecționează ieșirea standard către pipe-ul folosit de programul C
#exec > /dev/fd/3  # FD 3 este descriptorul de fișier asociat cu pipe-ul

# Verifică numărul de linii, cuvinte și caractere
num_lines=$(wc -l < "$file")
num_words=$(wc -w < "$file")
num_chars=$(wc -m < "$file")

# Verifică dacă fișierul este suspect
if [ "$num_lines" -lt "$min_lines" ] && [ "$num_words" -gt "$min_words" ] && [ "$num_chars" -gt "$min_chars" ]; then
    # Verifică dacă există caractere non-ASCII sau cuvinte cheie
    if grep -q -P '[^\x00-\x7F]' "$file" || grep -q -E 'corrupted|dangerous|risk|attack|malware|malicious' "$file"; then
        echo "$file MALICIOUS"
    else
        echo "$file SAFE"
    fi
else
    echo "$file SAFE"
fi

