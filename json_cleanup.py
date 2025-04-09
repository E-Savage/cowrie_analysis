import json

def clean_cowrie_logs(input_file, output_file):
    events = []
    with open(input_file, 'r') as infile:
        for line in infile:
            line = line.strip()
            if not line:
                continue  # Skip empty lines
            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError as e:
                print(f"Skipping bad line: {e}")

    with open(output_file, 'w') as outfile:
        json.dump(events, outfile, indent=4)

    print(f"Saved {len(events)} clean events to {output_file}")

if __name__ == "__main__":
    # --- <<< CHANGE THESE TWO NAMES >>> ---
    input_file = 'cowrie_master.json'   # your unclean log file
    output_file = 'clean_cowrie_logs.json'  # where you want clean output

    # Run the cleaner
    clean_cowrie_logs(input_file, output_file)
