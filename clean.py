import re

def clean_logs(input_file, output_file):
    # Define the ANSI escape sequence regex
    ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')
    
    # Read the input file and clean it
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            # Remove ANSI escape sequences
            clean_line = ansi_escape.sub('', line)
            outfile.write(clean_line)

# Usage
input_file = 'logs_automated.txt'  # Replace with your actual file path
output_file = 'logs_automated_clean.txt'
clean_logs(input_file, output_file)