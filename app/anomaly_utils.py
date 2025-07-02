def binary_search(sorted_list, target):
    low = 0
    high = len(sorted_list) - 1
    while low <= high:
        mid = (low + high) // 2
        if sorted_list[mid] == target:
            return True
        elif sorted_list[mid] < target:
            low = mid + 1
        else:
            high = mid - 1
    return False

def is_anomaly(value, known_values):
    normalized = [v.lower() for v in known_values]
    normalized.sort()
    return not binary_search(normalized, value.lower())
