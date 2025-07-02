def parse_log_file(content):
    entries = []
    lines = content.strip().split('\n')
    for line in lines:
        parts = line.split(',')
        if len(parts) >= 4:
            entry = {
                'timestamp': parts[0],
                'severity': parts[1],
                'user': parts[2],
                'message': parts[3],
                'hash': parts[4] if len(parts) > 4 else ''
            }
            entries.append(entry)
    return entries
