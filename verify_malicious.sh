#!/bin/bash

# Set permissions to read-only
chmod 400 "$1"

file_path="$1"
file_name="$2"
isolate_dir="Isolated"

# Count lines, words, and characters in the file
line_count=$(wc -l < "$file_path")
word_count=$(wc -w < "$file_path")
char_count=$(wc -c < "$file_path")

# Check if the file exists
if [ ! -f "$file_path" ]; then
    echo "File not found: $file_name"
    exit 1
fi

# Define keywords to check for suspicious content
keywords=("corrupted" "dangerous" "risk" "attack" "malware" "malicious")
suspect=0

# Check if the file meets the criteria for suspicion
if [ "$line_count" -lt 3 ] && [ "$word_count" -gt 10 ] && [ "$char_count" -gt 20 ]; then
    suspect=1
fi

# Check for keywords and non-ASCII characters if the file is suspected
if [ $suspect -eq 1 ]; then
    for keyword in "${keywords[@]}"; do
        if grep -q "$keyword" "$file_path"; then
            echo "$file_name"
            exit 0
        fi
    done

    # Check for non-ASCII characters
    if grep -q -P '[^\x00-\x7F]' "$file_path"; then
        echo "$file_name"
        exit 0
    fi

    echo "SAFE"
else
    echo "SAFE"
fi

# Reset permissions to no access
chmod 000 "$1"
