def split_file(file_path, size=4000):
    with open(file_path, 'r') as file:
        content = file.read()
    
    parts = [content[i:i+size] for i in range(0, len(content), size)]
    for index, part in enumerate(parts):
        with open(f'part_{index + 1}.txt', 'w') as file:
            file.write(part)

# Usage
split_file('/home/flintx/debugsafeway/four.py')  # Replace 'yourfile.txt' with your file path