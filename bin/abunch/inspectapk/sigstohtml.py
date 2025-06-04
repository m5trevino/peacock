import pandas as pd
import os

# Define security-related keywords and categories
SECURITY_CLASSES_KEYWORDS = {
    "SSL/TLS & Certificate Pinning": ["TrustManager", "CertificatePinner", "SSLContext", "X509TrustManager"],
    "Root Detection": ["java.io.File", "Runtime", "exec"],
    "WebView Security": ["WebView", "WebViewClient", "SslErrorHandler"],
    "Debugging Detection": ["Debug", "isDebuggerConnected"],
    "Network Security": ["NetworkSecurityConfig", "isCleartextTrafficPermitted"]
}

def generate_html_from_csv():
    # Prompt for CSV file path
    csv_file = input("Enter the path to the class-method CSV file: ").strip()

    # Check if CSV file exists
    if not os.path.isfile(csv_file):
        print(f"[-] Error: CSV file '{csv_file}' not found!")
        return

    # Prompt for output HTML file path
    output_html_file = input("Enter the output HTML file path (e.g., /path/to/classes.html): ").strip()

    # Load CSV data
    try:
        df = pd.read_csv(csv_file)
    except Exception as e:
        print(f"[-] Error reading CSV file: {e}")
        return

    # Ensure the required columns exist
    if 'class' not in df.columns or 'methods' not in df.columns:
        print("[-] Error: CSV file must have 'class' and 'methods' columns!")
        return

    # Prepare data structures
    security_classes = {category: [] for category in SECURITY_CLASSES_KEYWORDS.keys()}
    non_security_classes = []

    # Analyze classes and methods
    for _, row in df.iterrows():
        class_name = str(row['class']).strip()
        methods = str(row['methods']).strip()

        # Skip invalid class names
        if not class_name or class_name.lower() == 'nan':
            continue

        # Determine if the class is security-related
        categorized = False
        for category, keywords in SECURITY_CLASSES_KEYWORDS.items():
            if any(keyword in class_name for keyword in keywords):
                security_classes[category].append((class_name, methods))
                categorized = True
                break

        if not categorized:
            non_security_classes.append((class_name, methods))

    # Generate HTML content
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Class and Method Analysis</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            line-height: 1.6;
            background-color: #f4f4f4;
        }
        .container {
            max-width: 900px;
            margin: auto;
            padding: 20px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2 {
            text-align: center;
            color: #333;
        }
        h2 {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ddd;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 14px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #0073e6;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        tr:nth-child(odd) {
            background-color: #ffffff;
        }
        .security-category {
            color: #e63946;
        }
        .non-security-category {
            color: #2a9d8f;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>APK Class and Method Analysis</h1>

        <h2 class="security-category">Security-Related Classes and Methods</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Class Name</th>
                <th>Methods</th>
            </tr>
"""

    # Add security-related classes to HTML
    for category, classes in security_classes.items():
        if classes:
            for class_name, methods in classes:
                html_content += f"""
                <tr>
                    <td>{category}</td>
                    <td>{class_name}</td>
                    <td>
                        <ul>
                """
                method_list = methods.split("; ")
                for method in method_list:
                    method = method.strip()
                    if method:
                        html_content += f"<li>{method}</li>"

                html_content += """
                        </ul>
                    </td>
                </tr>
                """

    html_content += """
        </table>

        <h2 class="non-security-category">Other Classes and Methods</h2>
        <table>
            <tr>
                <th>Class Name</th>
                <th>Methods</th>
            </tr>
    """

    # Add non-security-related classes to HTML
    for class_name, methods in non_security_classes:
        html_content += f"""
        <tr>
            <td>{class_name}</td>
            <td>
                <ul>
        """
        method_list = methods.split("; ")
        for method in method_list:
            method = method.strip()
            if method:
                html_content += f"<li>{method}</li>"

        html_content += """
                </ul>
            </td>
        </tr>
        """

    # Close HTML tags
    html_content += """
        </table>
    </div>
</body>
</html>
"""

    # Save HTML content to the output file
    try:
        with open(output_html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] HTML file saved to {output_html_file}")
    except Exception as e:
        print(f"[-] Error saving HTML file: {e}")

# Run the script
if __name__ == "__main__":
    generate_html_from_csv()
