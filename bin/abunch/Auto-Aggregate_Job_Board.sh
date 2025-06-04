INPUTFILE="$1"

# Clean up carriage return characters from the input file
CLEANED_FILE=$(mktemp) # Create a temporary clean file
tr -d $'\r' < "$INPUTFILE" > "$CLEANED_FILE"

# Debug: Print confirmation and contents of the cleaned file
echo "Processing file after removing carriage returns: $CLEANED_FILE"
echo "Contents of cleaned file:"
cat "$CLEANED_FILE"

# Process the CSV file line by line. The 'tail -n +2' skips header row.
tail -n +2 "$CLEANED_FILE" | while IFS=, read -r AggregatorURL EmployerATSURL EmployerName Category
do
  # Trim leading/trailing spaces and validate variables
  AggregatorURL=$(echo "$AggregatorURL" | xargs)
  EmployerATSURL=$(echo "$EmployerATSURL" | xargs)
  EmployerName=$(echo "$EmployerName" | xargs)
  Category=$(echo "$Category" | xargs)

  # Skip the line if any required value is empty
  if [[ -z "$AggregatorURL" || -z "$EmployerATSURL" || -z "$EmployerName" || -z "$Category" ]]; then
    echo "WARNING: Missing data in line, skipping..."
    continue
  fi

  # Debug: Echo each value to verify
  echo "DEBUG: AggregatorURL=$AggregatorURL"
  echo "DEBUG: EmployerATSURL=$EmployerATSURL"
  echo "DEBUG: EmployerName=$EmployerName"
  echo "DEBUG: Category=$Category"

  # Call osascript and pass cleaned values
  osascript -e "
on run argv
  set aggregatorURL to item 1 of argv
  set employerATSURL to item 2 of argv
  set employerName to item 3 of argv
  set categoryVal to item 4 of argv

  -- Ensure Safari is running
  tell application \"Safari\"
    if not (exists window 1) then
      make new document
    end if
    set newTab to make new tab at end of tabs of window 1
    set URL of newTab to aggregatorURL
    set current tab of window 1 to newTab
  end tell

  delay 3 -- Wait for the page to load

  tell application \"System Events\"
    tell process \"Safari\"
      set frontmost to true

      -----------------------------------------------------------
      -- Step 1: Set Employer ATS URL
      -----------------------------------------------------------
      set atsField to first text field of front window whose value of attribute \"AXDescription\" is \"source_url\"
      set value of atsField to employerATSURL
      delay 2

      -----------------------------------------------------------
      -- Step 2: Set Employer Name
      -----------------------------------------------------------
      set employerNameField to first text field of front window whose value of attribute \"AXDescription\" is \"vs__selected\"
      set value of employerNameField to employerName
      delay 2

      -----------------------------------------------------------
      -- Step 3: Set Category
      -----------------------------------------------------------
      set categoryDropdown to first pop up button of front window whose value of attribute \"AXDescription\" is \"category_id[value]\"
      click categoryDropdown
      delay 2

      set categoryOption to first menu item of menu 1 of categoryDropdown whose title is categoryVal
      click categoryOption
      delay 2

      -----------------------------------------------------------
      -- Step 4: Click Update Button
      -----------------------------------------------------------
      set updateButton to first button of front window whose value of attribute \"AXTitle\" is \"Update\"
      perform action \"AXPress\" of updateButton
      delay 2
    end tell
  end tell

  delay 5 -- Small pause before processing the next row
end run" \
"$AggregatorURL" "$EmployerATSURL" "$EmployerName" "$Category"

done

# Clean up temporary file
rm "$CLEANED_FILE"