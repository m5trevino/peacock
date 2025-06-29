#!/bin/bash
# FIX 1PROMPT DASHBOARD - Update character counts and fix log links

echo "🔧 FIXING 1PROMPT DASHBOARD..."

# STEP 1: Update the 1prompt.py file to properly handle character counts
sed -i 's/document.getElementById('\''totalChars'\'').textContent = totalChars.toLocaleString();/document.getElementById('\''totalChars'\'').textContent = totalChars.toLocaleString();\n                    document.getElementById('\''sparkChars'\'').textContent = stageData.spark?.chars.toLocaleString() + " chars";\n                    document.getElementById('\''falconChars'\'').textContent = stageData.falcon?.chars.toLocaleString() + " chars";\n                    document.getElementById('\''eagleChars'\'').textContent = stageData.eagle?.chars.toLocaleString() + " chars";\n                    document.getElementById('\''hawkChars'\'').textContent = stageData.hawk?.chars.toLocaleString() + " chars";/' /home/flintx/peacock/core/1prompt.py

# STEP 2: Fix the log links to point to the correct location
sed -i 's|file:///home/flintx/peacock/logs/|file:///home/flintx/peacock/core/logs/|g' /home/flintx/peacock/core/1prompt.py

# STEP 3: Add links to mega prompt and final response logs
sed -i '/<div class="log-links">/a\
                    <a href="file:///home/flintx/peacock/core/logs/megapromptlog-${{sessionTimestamp}}.txt" class="log-link" target="_blank">🔥 Mega Prompt Log</a>\
                    <a href="file:///home/flintx/peacock/core/logs/finalresponselog-${{sessionTimestamp}}.txt" class="log-link" target="_blank">✅ Final Response Log</a>' /home/flintx/peacock/core/1prompt.py

# STEP 4: Fix the XEdit opening function to properly handle the path
sed -i 's/function openXEdit() {/function openXEdit() {\
            const xeditPath = `file:\/\/\/home\/flintx\/peacock\/html\/xedit-${sessionTimestamp}.html`;\
            window.open(xeditPath, "_blank");/' /home/flintx/peacock/core/1prompt.py

# STEP 5: Remove any existing openXEdit function body to avoid duplicates
sed -i '/if (pipelineResults && pipelineResults.xedit_interface/,/}/d' /home/flintx/peacock/core/1prompt.py

# STEP 6: Update the auto-open XEdit behavior
sed -i 's/pipelineResults = result;/pipelineResults = result;\n                    setTimeout(() => openXEdit(), 1000); \/\/ Auto-open XEdit after 1 second/' /home/flintx/peacock/core/1prompt.py

echo ""
echo "✅ 1PROMPT DASHBOARD FIXED!"
echo ""
echo "🔧 WHAT WAS FIXED:"
echo "   📊 Character counts now properly update for each bird"
echo "   🔗 Log links now point to the correct location"
echo "   🔥 Added links to mega prompt and final response logs"
echo "   🎯 Fixed XEdit opening function"
echo "   🚀 Added auto-open XEdit behavior"
echo ""
echo "🚀 TEST IT:"
echo "   python3 /home/flintx/peacock/core/1prompt.py"
echo "   # Then trigger a prompt and check that everything works!"