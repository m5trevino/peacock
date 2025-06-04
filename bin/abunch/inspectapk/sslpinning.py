import pandas as pd
import re
import sys

# Function to get file paths from arguments or prompt the user
def get_file_path(arg_index, prompt):
    try:
        return sys.argv[arg_index]
    except IndexError:
        return input(prompt)

# Get file paths from command-line arguments or prompt the user
classes_file = get_file_path(1, "Enter the full path to the classes CSV file: ")
methods_file = get_file_path(2, "Enter the full path to the methods CSV file: ")
output_combined_file = "combined_classes_methods.csv"
output_filtered_file = "ssl_pinning_related.csv"

# Keywords and patterns to search for
keywords = [
    "SSL", "TrustManager", "Pinner", "Certificate", "Keystore", "Secure", "Verifier", "Socket", "crypto"
]
method_keywords = [
    "checkServerTrusted", "verify", "getAcceptedIssuers", "SSLContext.init", "createSocket"
]
patterns = [
    r"-----BEGIN CERTIFICATE-----",  # PEM-like certificates
    r"MIIBIjANBgkqh[A-Za-z0-9+/]+={0,2}"  # Base64 public key (partial match)
]

# Step 1: Combine the CSVs
print("[*] Combining class and method CSV files...")
classes_df = pd.read_csv(classes_file)
methods_df = pd.read_csv(methods_file)

# Ensure they have the same number of lines
if len(classes_df) != len(methods_df):
    raise ValueError("Class and method CSVs do not have the same number of rows.")

# Combine into a single DataFrame
combined_df = pd.DataFrame({
    "class": classes_df["class"],
    "methods": methods_df["methods"]
})

# Save combined file
combined_df.to_csv(output_combined_file, index=False)
print(f"[+] Combined CSV saved to {output_combined_file}")

# Step 2: Scan for SSL and cert pinning indicators
print("[*] Scanning for SSL and certificate pinning indicators...")
def contains_keywords_or_patterns(row):
    # Check for keywords in class or method
    for keyword in keywords:
        if keyword.lower() in row["class"].lower() or keyword.lower() in row["methods"].lower():
            return True

    # Check for method-specific keywords
    for method_keyword in method_keywords:
        if method_keyword.lower() in row["methods"].lower():
            return True

    # Check for patterns in methods (e.g., PEM or Base64 strings)
    for pattern in patterns:
        if re.search(pattern, row["methods"]):
            return True

    return False

# Filter rows
filtered_df = combined_df[combined_df.apply(contains_keywords_or_patterns, axis=1)]

# Save filtered results
filtered_df.to_csv(output_filtered_file, index=False)
print(f"[+] Filtered SSL-related classes and methods saved to {output_filtered_file}")
