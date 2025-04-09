import json
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
from datetime import datetime
import os

# --- <<< CHANGE THIS IF NEEDED >>> ---
input_file = 'clean_cowrie_logs.json'  # your cleaned JSON file
output_folder = 'plots'  # where to save plots

# Create the output folder if it doesn't exist
os.makedirs(output_folder, exist_ok=True)

# Load the clean JSON data
with open(input_file, 'r') as f:
    events = json.load(f)

# === Function to save plot ===
def save_plot(name):
    plt.tight_layout()
    plt.savefig(os.path.join(output_folder, f"{name}.png"))
    plt.close()  # Close after saving so it doesn't pop up

# === 1. Top 5 Attacker IPs ===
src_ips = [event['src_ip'] for event in events if event.get('eventid') == 'cowrie.session.connect']
ip_counts = Counter(src_ips)

if ip_counts:
    top_ips, counts = zip(*ip_counts.most_common(5))

    plt.figure()
    plt.bar(top_ips, counts)
    plt.xticks(rotation=45)
    plt.title('Top 5 Attacker IPs')
    plt.xlabel('IP Address')
    plt.ylabel('Number of Connections')
    save_plot('top_5_attacker_ips')

# === 2. Top 5 SSH Client Versions ===
client_versions = [event['version'] for event in events if event.get('eventid') == 'cowrie.client.version']
version_counts = Counter(client_versions)

if version_counts:
    top_versions, version_counts_vals = zip(*version_counts.most_common(5))

    plt.figure()
    plt.bar(top_versions, version_counts_vals)
    plt.xticks(rotation=45)
    plt.title('Top 5 SSH Client Versions')
    plt.xlabel('SSH Client Version')
    plt.ylabel('Count')
    save_plot('top_5_ssh_client_versions')

# === 3. Session Duration Histogram ===
durations = []
for event in events:
    if event.get('eventid') == 'cowrie.session.closed':
        try:
            durations.append(float(event['duration']))
        except (KeyError, ValueError):
            continue

if durations:
    plt.figure()
    plt.hist(durations, bins=20, edgecolor='black')
    plt.title('Histogram of Session Durations')
    plt.xlabel('Duration (seconds)')
    plt.ylabel('Number of Sessions')
    save_plot('session_duration_histogram')

# === 4. Attacks Over Time ===
times = [event['timestamp'] for event in events if event.get('eventid') == 'cowrie.session.connect']
times_dt = [datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ") for ts in times]

if times_dt:
    # Count attacks per hour
    times_by_hour = [dt.replace(minute=0, second=0, microsecond=0) for dt in times_dt]
    hour_counts = Counter(times_by_hour)
    hours_sorted = sorted(hour_counts.keys())
    counts_sorted = [hour_counts[h] for h in hours_sorted]

    plt.figure()
    plt.plot(hours_sorted, counts_sorted, marker='o')
    plt.xticks(rotation=45)
    plt.title('Attacks Over Time (per hour)')
    plt.xlabel('Time')
    plt.ylabel('Number of Connections')
    save_plot('attacks_over_time')

# === 5. Common HASSH Fingerprints ===
hassh_vals = [event['hassh'] for event in events if event.get('eventid') == 'cowrie.client.kex' and 'hassh' in event]
hassh_counts = Counter(hassh_vals)

if hassh_counts:
    top_hassh, top_hassh_counts = zip(*hassh_counts.most_common(5))

    plt.figure()
    plt.bar(top_hassh, top_hassh_counts)
    plt.xticks(rotation=45)
    plt.title('Top 5 HASSH Fingerprints')
    plt.xlabel('HASSH Fingerprint')
    plt.ylabel('Count')
    save_plot('top_5_hassh_fingerprints')

# === 6. Session Durations by IP (Box Plot) ===
durations_by_ip = defaultdict(list)
for event in events:
    if event.get('eventid') == 'cowrie.session.closed' and 'src_ip' in event:
        try:
            durations_by_ip[event['src_ip']].append(float(event['duration']))
        except (KeyError, ValueError):
            continue

if durations_by_ip:
    ip_keys = list(durations_by_ip.keys())[:5]  # limit to 5 IPs
    duration_values = [durations_by_ip[ip] for ip in ip_keys]

    plt.figure()
    plt.boxplot(duration_values, labels=ip_keys)
    plt.xticks(rotation=45)
    plt.title('Session Durations by Top IPs')
    plt.xlabel('IP Address')
    plt.ylabel('Duration (seconds)')
    save_plot('session_durations_by_ip')

# === 7. Failed vs Successful Sessions ===
quick_disconnects = 0
long_sessions = 0
for dur in durations:
    if dur < 0.5:
        quick_disconnects += 1
    else:
        long_sessions += 1

if quick_disconnects + long_sessions > 0:
    plt.figure()
    plt.pie([quick_disconnects, long_sessions], labels=['Quick Disconnects', 'Long Sessions'], autopct='%1.1f%%')
    plt.title('Failed vs Successful Sessions')
    save_plot('failed_vs_successful_sessions')

print(f"Plots saved in the '{output_folder}' folder.")
