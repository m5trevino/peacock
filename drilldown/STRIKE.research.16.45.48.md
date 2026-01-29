### STRATEGIC BLUEPRINT: CASEFLOW PRO

**1. PRIME DIRECTIVE**
Deploy a high-performance, AI-enhanced legal research platform capable of searching and indexing 1,135 cross-referenced documents across Ada and Latah counties with instant PDF retrieval.

**2. CORE ENGINE**
The system utilizes a client-side state machine that flattens a multi-dimensional JavaScript object (`enhancedDocumentData`) partitioned by [County] and [Year]. The search engine performs real-time semantic filtering across four vectors: Document Name, AI-generated Summaries, Document Type, and Key Terms.

**3. TECHNICAL DNA**
*   **Frontend Stack:** Vanilla HTML5, CSS3 (Custom Variables), ES6+ JavaScript.
*   **Data Architecture:** `enhanced_document_database.js` (Primary Object) and `search_index.json` (Cross-references).
*   **Backend/Hosting:** Python3 HTTP Server (`http.server`) bound to port 8080.
*   **File System Authority:** 
    *   Root: `/home/flintx/kobanger/`
    *   Webroot: `/home/flintx/kobanger/webapp/`
    *   Assets: `/webapp/js/` and `/webapp/data/`

**4. UI/UX SPECIFICATION**
*   **Theme:** "Legal Cyberpunk" (Dark Mode).
*   **Palette:** Background `#0a0a0f`, Secondary `#1a1a2e`, Accent Cyan `#00d4ff`, Text `#ffffff`.
*   **Typography:** JetBrains Mono / Arial fallback.
*   **Layout:** Centered search container with real-time database status indicator and vertical result cards.

**5. OPERATIONAL WORKFLOW**
1.  **Initialization:** Server starts and validates `enhancedDocumentData` presence.
2.  **Indexing:** Frontend flattens county/year nested data into a searchable array.
3.  **Query:** User inputs term (e.g., "Motion", "DNA").
4.  **Triage:** Engine filters array and slices top 15-20 results for performance.
5.  **Retrieval:** User clicks "View PDF" to open the document via the hosted `api.mountmaster.pro` URL.

**6. INTEL VAULT**
*   **User Context:** High-stakes legal environment; zero tolerance for "relative path" errors or browser caching issues.
*   **Data Volume:** 1,135 Documents, 7,460 Cross-references.
*   **Note:** If the webapp appears empty despite a successful server start, a hard browser refresh (Ctrl+Shift+R) is mandatory to bypass cached artifacts.

---

### DEPLOYMENT AND RECOVERY SCRIPTS

```bash
cat << 'EOF' > /home/flintx/kobanger/webapp/index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CaseFlow Pro - 1,135 Documents</title>
    <style>
        body { 
            background: #0a0a0f; 
            color: white; 
            font-family: Arial; 
            margin: 0; 
            padding: 20px; 
        }
        .container { 
            max-width: 1000px; 
            margin: 0 auto; 
        }
        h1 { 
            color: #00d4ff; 
            text-align: center; 
            margin-bottom: 10px; 
        }
        .subtitle { 
            text-align: center; 
            color: #b8c5d6; 
            margin-bottom: 30px; 
        }
        .search-box { 
            width: 100%; 
            padding: 15px; 
            font-size: 16px; 
            background: #1a1a2e; 
            border: 2px solid #2d3748; 
            color: white; 
            border-radius: 8px; 
            margin-bottom: 10px; 
        }
        .search-btn { 
            background: #00d4ff; 
            color: #0a0a0f; 
            padding: 15px 30px; 
            border: none; 
            border-radius: 8px; 
            font-size: 16px; 
            font-weight: bold; 
            cursor: pointer; 
        }
        .search-btn:hover { 
            background: #00b8e6; 
        }
        .results { 
            margin-top: 30px; 
        }
        .doc-card { 
            background: #1a1a2e; 
            border: 1px solid #2d3748; 
            padding: 20px; 
            margin: 15px 0; 
            border-radius: 8px; 
        }
        .doc-title { 
            color: #00d4ff; 
            font-weight: bold; 
            margin-bottom: 10px; 
            font-size: 18px; 
        }
        .doc-summary { 
            color: #b8c5d6; 
            margin-bottom: 15px; 
            line-height: 1.4; 
        }
        .doc-meta { 
            color: #6c7b8a; 
            font-size: 14px; 
        }
        .doc-link { 
            color: #00d4ff; 
            text-decoration: none; 
        }
        .doc-link:hover { 
            text-decoration: underline; 
        }
        .status { 
            background: #16213e; 
            padding: 10px; 
            border-radius: 5px; 
            margin-bottom: 20px; 
            border-left: 4px solid #00d4ff; 
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>CaseFlow Pro</h1>
        <div class="subtitle">Searching 1,135 Legal Documents with AI</div>
        
        <div id="dbStatus" class="status">Loading database...</div>
        
        <input type="text" class="search-box" id="searchInput" placeholder="Search documents (try: motion, DNA, warrant, court order)">
        <button class="search-btn" onclick="search()">Search</button>
        
        <div id="results" class="results"></div>
    </div>
    
    <script src="js/enhanced_document_database.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const status = document.getElementById('dbStatus');
            if (typeof enhancedDocumentData !== 'undefined') {
                let totalDocs = 0;
                Object.keys(enhancedDocumentData).forEach(county => {
                    Object.keys(enhancedDocumentData[county]).forEach(year => {
                        totalDocs += enhancedDocumentData[county][year].length;
                    });
                });
                status.innerHTML = `✅ Database loaded: ${totalDocs} documents from ${Object.keys(enhancedDocumentData).join(', ')} counties`;
                status.style.borderColor = '#00ff88';
            } else {
                status.innerHTML = '❌ Database failed to load!';
                status.style.borderColor = '#ff6b35';
            }
        });

        function search() {
            const query = document.getElementById('searchInput').value.trim().toLowerCase();
            const resultsDiv = document.getElementById('results');
            if (!query) {
                resultsDiv.innerHTML = '<div class="doc-card">Please enter a search term</div>';
                return;
            }
            let allDocs = [];
            Object.keys(enhancedDocumentData).forEach(county => {
                Object.keys(enhancedDocumentData[county]).forEach(year => {
                    enhancedDocumentData[county][year].forEach(doc => {
                        allDocs.push({ ...doc, county: county, year: year });
                    });
                });
            });
            const results = allDocs.filter(doc => {
                if (!doc) return false;
                return (
                    (doc.name && doc.name.toLowerCase().includes(query)) ||
                    (doc.ai_summary && doc.ai_summary.toLowerCase().includes(query)) ||
                    (doc.type && doc.type.toLowerCase().includes(query)) ||
                    (doc.key_terms && doc.key_terms.some(term => term.toLowerCase().includes(query)))
                );
            });
            if (results.length === 0) {
                resultsDiv.innerHTML = `<div class="doc-card"><div class="doc-title">No results found for "${query}"</div></div>`;
            } else {
                resultsDiv.innerHTML = `<div class="doc-card"><div class="doc-title">Found ${results.length} results for "${query}"</div></div>`;
                results.slice(0, 15).forEach(doc => {
                    resultsDiv.innerHTML += `
                        <div class="doc-card">
                            <div class="doc-title">${doc.name || 'Untitled Document'}</div>
                            <div class="doc-summary">${(doc.ai_summary || 'No summary available').substring(0, 300)}...</div>
                            <div class="doc-meta">
                                📁 ${doc.county.toUpperCase()} County • 📅 ${doc.year} • 📄 ${doc.type || 'Document'}
                                <br><a href="${doc.url}" target="_blank" class="doc-link">📖 View PDF Document →</a>
                            </div>
                        </div>`;
                });
            }
        }
        document.getElementById('searchInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') search();
        });
    </script>
</body>
</html>
EOF
```

```bash
cat << 'EOF' > /home/flintx/kobanger/deploy_webapp.sh
#!/bin/bash
# CaseFlow Pro Deployment Script
WEBROOT="/home/flintx/kobanger/webapp"
SOURCE="/home/flintx/kobanger"

mkdir -p $WEBROOT/js $WEBROOT/data

cp $SOURCE/enhanced_document_database.js $WEBROOT/js/
cp $SOURCE/search_index.json $WEBROOT/data/

cd $WEBROOT
pkill -f "python3 -m http.server 8080"
python3 -m http.server 8080
EOF
chmod +x /home/flintx/kobanger/deploy_webapp.sh
```