
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib_venn import venn2, venn2_circles
import re

def normalize_crash_line(crash_line):
    """
    Normalize crash lines to enable comparison between different E2AP versions.
    Removes version-specific paths and normalizes directory structures.
    """
    if not isinstance(crash_line, str):
        return ''
    
    # Remove version-specific paths (v2_03, v1_01) and normalize paths
    normalized = crash_line
    normalized = re.sub(r'/v2_03/', '/vX_XX/', normalized)
    normalized = re.sub(r'/v1_01/', '/vX_XX/', normalized)
    normalized = re.sub(r'/home/asset/ns3', '', normalized)
    normalized = normalized.strip()
    
    return normalized

def extract_nearrt_ric_crashes(df):
    """
    Extract and normalize nearRT-RIC crashes from a DataFrame.
    Only includes crashes that start with 'nearRT-RIC'.
    """
    # Filter for nearRT-RIC crashes
    nearrt_crashes = df[df['Crash Line'].str.startswith('nearRT-RIC', na=False)]
    
    # Normalize crash lines
    normalized_crashes = nearrt_crashes['Crash Line'].apply(normalize_crash_line)
    
    # Remove duplicates and return as set
    return set(normalized_crashes.dropna())

def create_venn_diagram(file1_path, file2_path, output_path='venn_diagram.png'):
    """
    Create a Venn diagram showing the overlap of bugs between two CSV files.
    """
    # Read the CSV files
    print(f"Reading {file1_path}...")
    df1 = pd.read_csv(file1_path, sep=',')
    
    print(f"Reading {file2_path}...")
    df2 = pd.read_csv(file2_path, sep=',')
    
    # Extract nearRT-RIC crashes
    crashes1 = extract_nearrt_ric_crashes(df1)
    crashes2 = extract_nearrt_ric_crashes(df2)
    
    print(f"\nFound {len(crashes1)} unique nearRT-RIC crashes in file 1")
    print(f"Found {len(crashes2)} unique nearRT-RIC crashes in file 2")
    
    # Calculate intersections
    intersection = crashes1.intersection(crashes2)
    only_in_file1 = crashes1 - crashes2
    only_in_file2 = crashes2 - crashes1
    
    print(f"\nVenn diagram analysis:")
    print(f"- Intersection (both files): {len(intersection)}")
    print(f"- Only in file 1: {len(only_in_file1)}")
    print(f"- Only in file 2: {len(only_in_file2)}")

    # Create the Venn diagram
    plt.figure(figsize=(10, 6))
    
    # Create Venn diagram
    venn = venn2(subsets=(len(only_in_file1), len(only_in_file2), len(intersection)), 
                 set_labels=('OAI (E2AP v2.03)\ndev branch', 'NS3(E2AP v1.01)\noie-ric-taap-xapps branch'))
    
    # Customize colors
    if venn.get_patch_by_id('10'):
        venn.get_patch_by_id('10').set_facecolor('#ff9999')
        venn.get_patch_by_id('10').set_edgecolor('black')
        venn.get_patch_by_id('10').set_linewidth(2)
    
    if venn.get_patch_by_id('01'):
        venn.get_patch_by_id('01').set_facecolor('#99ccff')
        venn.get_patch_by_id('01').set_edgecolor('black')
        venn.get_patch_by_id('01').set_linewidth(2)
    
    if venn.get_patch_by_id('11'):
        venn.get_patch_by_id('11').set_facecolor('#99ff99')
        venn.get_patch_by_id('11').set_edgecolor('black')
        venn.get_patch_by_id('11').set_linewidth(2)
    
    # Add title and labels
    plt.title('nearRT-RIC Crashes: E2AP Version Comparison\n', 
              fontsize=16, fontweight='bold', pad=20)
    
    # Adjust layout and save
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.show()
    
    # Print detailed intersection analysis
    if intersection:
        print(f"\nCommon crashes found in both versions:")
        for i, crash in enumerate(intersection, 1):
            print(f"\n{i}. {crash}")
    
    if only_in_file1:
        print(f"\nExamples of crashes only in E2AP v2.03:")
        for i, crash in enumerate(list(only_in_file1)[:3], 1):
            print(f"\n{i}. {crash}")
    
    if only_in_file2:
        print(f"\nExamples of crashes only in E2AP v1.01:")
        for i, crash in enumerate(list(only_in_file2)[:3], 1):
            print(f"\n{i}. {crash}")
    
    return {
        'intersection': intersection,
        'only_in_file1': only_in_file1,
        'only_in_file2': only_in_file2,
        'total_crashes1': len(crashes1),
        'total_crashes2': len(crashes2)
    }

def main():
    """
    Main function to run the Venn diagram analysis.
    """

    file2_path = '/media/p3rplex/data7/Logs_ORANCLAW/Logs_NS3/all_crashes_comparisonns3.csv'
    file1_path = '/media/p3rplex/data7/Logs_ORANCLAW/LogsOAI/all_crashes_comparisonOAI.csv'

    output_path = 'e2ap_crashes_venn_diagram.png'
    
    try:
        results = create_venn_diagram(file1_path, file2_path, output_path)
        print(f"\nVenn diagram saved as: {output_path}")
        return results
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please make sure the CSV files exist in the current directory.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Install required packages if not already installed
    print("Required packages: pandas, matplotlib, matplotlib-venn")
    print("Install with: pip install pandas matplotlib matplotlib-venn")
    print("-" * 50)
    
    main()