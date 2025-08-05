#!/bin/bash

capture_dir="/media/p3rplex/data7/Backup_ubuntu22/oran-orchestration/asn1/captures_bridge"

# Collect and sort timestamps
timestamps=$(find "$capture_dir" -maxdepth 1 -name 'session_*.pcapng' | \
  sed -E 's|.*/session_([0-9-]+_[0-9-]+)\.pcapng|\1|' | sort)

if [[ -z "$timestamps" ]]; then
  echo "No matching .pcapng files found in $capture_dir"
  exit 1
fi

# unique timestamps
unique_count=$(echo "$timestamps" | wc -l)

# oldest and newest timestamps
oldest=$(echo "$timestamps" | head -1)
newest=$(echo "$timestamps" | tail -1)

oldest_fmt=$(echo "$oldest" | sed 's/_/ /; s/-/:/3; s/-/:/3')
newest_fmt=$(echo "$newest" | sed 's/_/ /; s/-/:/3; s/-/:/3')

# Convert to epoch secs
oldest_sec=$(date -d "$oldest_fmt" +%s)
newest_sec=$(date -d "$newest_fmt" +%s)

# Calculate time difference
diff_sec=$((newest_sec - oldest_sec))
diff_hours=$((diff_sec / 3600))
diff_minutes=$(( (diff_sec % 3600) / 60 ))

echo "Unique timestamps: $unique_count"
echo "Oldest: $oldest"
echo "Newest: $newest"
echo "Difference: ${diff_hours} hours and ${diff_minutes} minutes"