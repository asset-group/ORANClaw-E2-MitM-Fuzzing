import re

def clean_logs(input_file, output_file):
    ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')
    
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            clean_line = ansi_escape.sub('', line)
            outfile.write(clean_line)

input_file = 'logs_core.txt'  
output_file = 'logs_core_clean.txt'
clean_logs(input_file, output_file)