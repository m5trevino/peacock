      
# --- Command to Compress Safely ---

# 1. Define where you wanna stash the compressed file (e.g., your home directory)
BACKUP_DEST="$HOME"

# 2. Create a timestamped filename so you know when you made it
FILENAME="abunch_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
OUTPUT_FILE="$BACKUP_DEST/$FILENAME"

# 3. The actual command
echo "[*] Compressing '/home/flintx/bin/abunch' to '$OUTPUT_FILE'..."
tar czvf "$OUTPUT_FILE" -C /home/flintx/bin abunch

# 4. Check if it worked
if [ $? -eq 0 ]; then
  echo "[+] Successfully compressed to: $OUTPUT_FILE"
  ls -lh "$OUTPUT_FILE" # Show the size, keep it 100
else
  echo "[!] Compression FAILED! Check for errors above."
fi

    
