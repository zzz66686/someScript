#!/bin/bash

# Define the pattern to search for
PATTERN="SecCtx_ComAuthKeyEx"

# Recursively process each file in the current directory and subdirectories
find /mnt/dji/apps -type f | while read -r file; do
    # Use strings to extract readable text and grep for the pattern
    result=$(/usr/bin/toybox strings "$file" | grep "$PATTERN")
    # echo "File: $file"
    # If there's a match, print the file name and grep result
    if [[ -n $result ]]; then
        echo "File: $file"
        echo "$result"
        echo "--------------------"
    fi
done
