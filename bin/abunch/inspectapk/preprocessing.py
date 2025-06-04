#!/usr/bin/env python3

import pandas as pd
import re
import os

def preprocess_combined_csv(input_file):
    """
    Preprocess the combined CSV file to clean and validate the data.
    Saves a cleaned CSV and a report summarizing the findings based on the input filename.
    """
    print(f"[*] Loading file: {input_file}")
    try:
        # Load the combined CSV
        df = pd.read_csv(input_file)

        # Check for missing or invalid data
        print("[*] Checking for missing or invalid data...")
        total_rows = len(df)
        invalid_rows = df[(df['class'].isnull()) | (df['methods'].isnull())]
        valid_rows = df.dropna()

        # Normalize class names and methods
        print("[*] Normalizing data...")
        valid_rows['class'] = valid_rows['class'].str.strip()
        valid_rows['methods'] = valid_rows['methods'].str.strip()

        # Flag and count "no method extracted"
        no_methods_count = valid_rows[valid_rows['methods'] == 'no method extracted'].shape[0]

        # Identify any methods that don't match a typical signature
        print("[*] Validating method signatures...")
        method_pattern = re.compile(r'[\w<>]+\s+\w+\([^)]*\)')
        valid_rows['valid_method'] = valid_rows['methods'].apply(
            lambda x: 'valid' if method_pattern.search(x) or x == 'no method extracted' else 'invalid'
        )
        invalid_methods = valid_rows[valid_rows['valid_method'] == 'invalid']

        # Save cleaned data
        base_name = os.path.splitext(os.path.basename(input_file))[0]
        output_file = f"{base_name}_cleaned.csv"
        cleaned_data = valid_rows[valid_rows['valid_method'] == 'valid'].drop(columns=['valid_method'])
        cleaned_data.to_csv(output_file, index=False)

        # Generate a report
        report_file = f"{base_name}_report.txt"
        print(f"[*] Generating report: {report_file}")
        with open(report_file, 'w') as report:
            report.write(f"Total rows: {total_rows}\n")
            report.write(f"Valid rows: {len(cleaned_data)}\n")
            report.write(f"Rows with missing data: {len(invalid_rows)}\n")
            report.write(f"Rows with 'no method extracted': {no_methods_count}\n")
            report.write(f"Rows with invalid methods: {len(invalid_methods)}\n")

        print(f"[+] Preprocessing completed successfully!")
        print(f"    Cleaned data saved to: {os.path.abspath(output_file)}")
        print(f"    Report saved to: {os.path.abspath(report_file)}")

    except Exception as e:
        print(f"[-] Error during preprocessing: {str(e)}")

if __name__ == "__main__":
    input_file = input("Enter the path to the combined CSV file: ").strip()

    if not os.path.isfile(input_file):
        print(f"[-] Error: {input_file} is not a valid file.")
        exit(1)

    preprocess_combined_csv(input_file)
