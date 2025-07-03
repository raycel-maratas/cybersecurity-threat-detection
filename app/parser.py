def parse_log_file(content):
    entries = []
    lines = content.strip().split('\n')
    for line in lines:
        parts = line.strip().split(',')
        if len(parts) >= 4:
            entry = {
                'timestamp': parts[0].strip(),
                'severity': parts[1].strip(),
                'user': parts[2].strip(),
                'message': parts[3].strip(),
                'hash': parts[4].strip() if len(parts) > 4 else ''
            }
            entries.append(entry)
    return entries
