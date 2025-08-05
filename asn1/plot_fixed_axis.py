import os
import re
import csv
from datetime import datetime
import matplotlib.pyplot as plt
from collections import defaultdict

# === Configuration ===
LOG_DIR_NO_OPT = "/home/p3rplex/Desktop/Logs_ORANCLAW/LogsOAI/wo_bug/24hrnoOptOAI/container_logs"
LOG_DIR_OPT = "/home/p3rplex/Desktop/Logs_ORANCLAW/LogsOAI/wo_bug/24hroptOAI/container_logs"
LOG_DIR_RAND = "/home/p3rplex/Desktop/Logs_ORANCLAW/LogsOAI/wo_bug/random/container_logs"

CRASH_KEYWORDS = [".c:", "/oai/openair2/", "/flexric/src", "(core dumped)"]
IGNORE_PATTERN = "xapp-kpm-monitor"

# CSV output files for each scenario
CSV_NO_OPT = "unique_crashes_no_opt.csv"
CSV_OPT = "unique_crashes_opt.csv"
CSV_RAND = "unique_crashes_random.csv"
CSV_ALL = "all_crashes_comparison.csv"

# === Helpers ===

def is_relevant_file(filename):
    return (
        filename.startswith("oran-orchestration-") and 
        IGNORE_PATTERN not in filename and 
        filename.endswith(".log")
    )

def extract_timestamp(filename):
    match = re.search(r'_(\d{8}_\d{6})_', filename)
    if match:
        return datetime.strptime(match.group(1), "%Y%m%d_%H%M%S")
    return None

def is_crash_line(line):
    if not any(keyword in line for keyword in CRASH_KEYWORDS):
        return False
    
    false_positive_patterns = [
        r"Assertion.*ProtocolIE_ID_id_.*failed",
        r"Assertion.*->id == ProtocolIE_ID.*failed",
        r"Assertion.*protocolIEs\.list\.count == \d+.*failed",
        #r"Assertion.*Criticality_reject.*failed"
    ]
    
    for pattern in false_positive_patterns:
        if re.search(pattern, line):
            return False
    
    return True

# === Main Processing Function ===

def process_logs_and_save(log_dir, csv_filename, start_time, end_time, label, color):
    """Process logs from a directory and save unique crashes to CSV"""
    print(f"Processing {label}...")
    
    # Collect all crash entries
    entries = []
    for fname in sorted(os.listdir(log_dir)):
        if not is_relevant_file(fname):
            continue
        ts = extract_timestamp(fname)
        if not ts:
            continue

        fpath = os.path.join(log_dir, fname)
        try:
            with open(fpath, 'r', errors='ignore') as f:
                for line in f:
                    if is_crash_line(line):
                        entries.append((ts, line.strip(), fname))
        except Exception as e:
            print(f"Error reading {fname}: {e}")

    crash_count = defaultdict(int)
    for _, line, _ in entries:
        crash_count[line] += 1

    # Extract unique entries with timestamps (first occurrence of each unique crash)
    unique_crashes = set()
    unique_entries = []

    for ts, line, fname in sorted(entries):
        if line not in unique_crashes:
            unique_crashes.add(line)
            unique_entries.append((ts, line, fname, crash_count[line]))

    # Save to CSV
    with open(csv_filename, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Timestamp", "Crash Line", "Source File", "Total Count"])
        for ts, line, fname, count in unique_entries:
            writer.writerow([ts.strftime("%Y-%m-%d %H:%M:%S"), line, fname, count])

    print(f"[✓] {label}: {len(unique_crashes)} unique crashes saved to {csv_filename}")

    times = [entry[0] for entry in unique_entries]
    cumulative_counts = list(range(1, len(unique_crashes) + 1))

    hours_from_start = [
        (ts - start_time).total_seconds() / 3600  
        for ts in times
    ]

    if hours_from_start and hours_from_start[0] > 0:
        hours_from_start.insert(0, 0.0)
        cumulative_counts.insert(0, 0)

    if hours_from_start and hours_from_start[-1] < 24:
        hours_from_start.append(24.0)
        cumulative_counts.append(cumulative_counts[-1])
    elif not hours_from_start:
        hours_from_start = [0.0, 24.0]
        cumulative_counts = [0, 0]

    return hours_from_start, cumulative_counts, label, color, unique_entries

# === Process Each Scenario ===

# Process No Optimization scenario
hours_no_opt, counts_no_opt, label_no_opt, color_no_opt, entries_no_opt = process_logs_and_save(
    LOG_DIR_NO_OPT,
    CSV_NO_OPT,
    datetime.strptime("2025-06-17_11-52-44", "%Y-%m-%d_%H-%M-%S"),
    datetime.strptime("2025-06-18_12-11-58", "%Y-%m-%d_%H-%M-%S"),
    "No Optimization",
    'green'
)

# Process Optimization scenario
hours_opt, counts_opt, label_opt, color_opt, entries_opt = process_logs_and_save(
    LOG_DIR_OPT,
    CSV_OPT,
    datetime.strptime("2025-06-17_15-07-41", "%Y-%m-%d_%H-%M-%S"),
    datetime.strptime("2025-06-18_11-55-50", "%Y-%m-%d_%H-%M-%S"),
    "Optimization",
    'blue'
)

# Process Random scenario
hours_rand, counts_rand, label_rand, color_rand, entries_rand = process_logs_and_save(
    LOG_DIR_RAND,
    CSV_RAND,
    datetime.strptime("2025-06-22_13-16-08", "%Y-%m-%d_%H-%M-%S"),
    datetime.strptime("2025-06-23_09-25-21", "%Y-%m-%d_%H-%M-%S"),
    "Random",
    'orange'
)

# === Create Combined CSV for Comparison (Deduplicated) ===
print("Creating combined comparison CSV with unique crashes only...")

# Collect all unique crashes across all scenarios
all_unique_crashes = {}  # crash_line -> (first_timestamp, first_scenario, first_source_file, scenarios_found)

# Track which scenarios each crash appears in
for scenario_name, entries in [("No Optimization", entries_no_opt), 
                               ("Optimization", entries_opt), 
                               ("Random", entries_rand)]:
    for ts, line, fname, count in entries:
        if line not in all_unique_crashes:
            # First time seeing this crash
            all_unique_crashes[line] = (ts, scenario_name, fname, [scenario_name])
        else:
            # Crash seen before, add scenario to list if not already there
            existing_ts, existing_scenario, existing_fname, scenarios_list = all_unique_crashes[line]
            if scenario_name not in scenarios_list:
                scenarios_list.append(scenario_name)
            # Keep the earliest timestamp
            if ts < existing_ts:
                all_unique_crashes[line] = (ts, scenario_name, fname, scenarios_list)

# Sort by first occurrence timestamp
sorted_unique_crashes = sorted(all_unique_crashes.items(), key=lambda x: x[1][0])

with open(CSV_ALL, mode='w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["First Timestamp", "Crash Line", "First Source File", "First Found In", "Also Found In", "Total Scenarios"])
    
    for crash_line, (first_ts, first_scenario, first_fname, scenarios_list) in sorted_unique_crashes:
        other_scenarios = [s for s in scenarios_list if s != first_scenario]
        also_found_in = "; ".join(other_scenarios) if other_scenarios else "None"
        
        writer.writerow([
            first_ts.strftime("%Y-%m-%d %H:%M:%S"), 
            crash_line, 
            first_fname, 
            first_scenario,
            also_found_in,
            len(scenarios_list)
        ])

print(f"[✓] Combined deduplicated comparison saved to {CSV_ALL}")
print(f"    Total unique crashes across all scenarios: {len(all_unique_crashes)}")

# === Plotting ===
plt.figure(figsize=(10, 6))
ax = plt.gca()

# Calculate plot limits
all_hours = hours_no_opt + hours_opt + hours_rand
all_counts = counts_no_opt + counts_opt + counts_rand

xmax = 24  # Fixed to 24 hours for all scenarios
ymax = max(all_counts) + 5 if all_counts else 30

# Set limits to ensure axes start at 0
ax.set_xlim([0, 24])
ax.set_ylim([0, ymax])

# Plot each scenario
plt.step(hours_no_opt, counts_no_opt, where='post', color=color_no_opt, linewidth=2, label=label_no_opt)
plt.step(hours_opt, counts_opt, where='post', color=color_opt, linewidth=2, label=label_opt)
plt.step(hours_rand, counts_rand, where='post', color=color_rand, linewidth=2, label=label_rand)

plt.title("Crashes Over Time - OpenAirInterface (OAI) - 1 Mutation Enabled")
plt.xlabel("Time (Hours)")
plt.ylabel("Cumulative Unique Crashes")
plt.grid(True, alpha=0.3)
plt.legend(loc="lower right")

# Add hour markers on x-axis
plt.xticks(range(0, 25, 2))  # Every 2 hours from 0 to 24

plt.tight_layout()

# Save and show plot
#plt.savefig("unique_crashes_time_comparison.png", dpi=300, bbox_inches='tight')
plt.show()

# === Summary Report ===
print("\n" + "="*60)
print("SUMMARY REPORT")
print("="*60)
print(f"No Optimization scenario: {len(entries_no_opt)} unique crashes")
print(f"Optimization scenario:    {len(entries_opt)} unique crashes")
print(f"Random scenario:          {len(entries_rand)} unique crashes")
print(f"Total unique crashes across all scenarios: {len(all_unique_crashes)}")
print("\nFiles generated:")
print(f"- {CSV_NO_OPT}")
print(f"- {CSV_OPT}")
print(f"- {CSV_RAND}")
print(f"- {CSV_ALL} (deduplicated)")
print(f"- unique_crashes_time_comparison.png")
print("="*60)