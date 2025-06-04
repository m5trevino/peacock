#!/bin/bash
echo "Fetching Frida scripts..."
scripts=(/home/flintx/obrida/frida-scripts/*.js)
echo "Available scripts:"
select script in "${scripts[@]}"; do
    if [[ -n "$script" ]]; then
        echo "Selected script: $script"
        read -p "Enter the process name or PID: " process
        frida -U -n "$process" -s "$script"
        break
    fi
done

