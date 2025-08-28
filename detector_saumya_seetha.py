import csv
import json
import re
import sys
from typing import Dict, Any, Tuple, Set

# --- Regular Expressions for PII Detection ---
# Standalone PII: These are always considered PII.
PHONE_REGEX = re.compile(r'\b\d{10}\b')
AADHAR_REGEX = re.compile(r'\b\d{12}\b')
PASSPORT_REGEX = re.compile(r'\b[A-Z]\d{7}\b')
UPI_REGEX = re.compile(r'\b[\w.-]+@(?:ybl|paytm|okaxis|ibl|axl|upi|oksbi)\b', re.IGNORECASE)

# Combinatorial PII: These become PII when two or more are present.
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
IPV4_REGEX = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
ADDRESS_INDICATORS = ['road', 'street', 'lane', 'avenue', 'nagar', 'colony', 'sector']

# --- Redaction Functions ---

def redact_name(name: str) -> str:
    """Redacts a name, preserving only the first letter."""
    if not name or not isinstance(name, str):
        return name
    
    parts = name.split()
    if len(parts) == 1:
        return f"{parts[0][0]}{'X' * (len(parts[0])-1)}" if len(parts[0]) > 1 else parts[0]
    
    redacted_parts = []
    for part in parts:
        if len(part) > 1:
            redacted_parts.append(f"{part[0]}{'X' * (len(part)-1)}")
        else:
            redacted_parts.append(part)
    
    return " ".join(redacted_parts)

def redact_email(email: str) -> str:
    """Redacts an email address, preserving the first 2 characters before @."""
    try:
        user, domain = email.split('@')
        if len(user) <= 2:
            return f"{user}@{domain}"
        return f"{user[:2]}{'X' * (len(user)-2)}@{domain}"
    except ValueError:
        return f"{'X' * len(email)}"

def redact_phone(phone: str) -> str:
    """Redacts a phone number, preserving first 2 and last 2 digits."""
    if len(phone) != 10:
        return phone
    return f"{phone[:2]}{'X' * 6}{phone[-2:]}"

def redact_aadhar(aadhar: str) -> str:
    """Redacts an Aadhar number, preserving first 4 and last 4 digits."""
    if len(aadhar) != 12:
        return aadhar
    return f"{aadhar[:4]}{'X' * 4}{aadhar[-4:]}"

def redact_upi(upi: str) -> str:
    """Redacts a UPI ID."""
    if '@' in upi:
        user, domain = upi.split('@')
        if len(user) <= 2:
            return f"{'X' * len(user)}@{domain}"
        return f"{user[0]}{'X' * (len(user)-2)}{user[-1]}@{domain}"
    return f"{'X' * len(upi)}"

def redact_address(address: str) -> str:
    """Redacts an address while preserving some structure."""
    if not address or not isinstance(address, str):
        return address
    
    # Simple approach: replace alphanumeric sequences with X's but keep separators
    redacted = re.sub(r'[A-Za-z0-9]+', lambda m: 'X' * len(m.group()), address)
    return redacted

def redact_ip(ip: str) -> str:
    """Redacts an IP address."""
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.XXX.XXX.{parts[3]}"
    return ip

# --- Main Detection Logic ---

def process_record(data: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """
    Processes a single JSON record to detect and redact PII.
    Returns a tuple containing:
    1. The redacted data dictionary.
    2. A boolean indicating if PII was found.
    """
    redacted_data = data.copy()
    is_pii = False
    
    # Track found PII types
    found_pii_types = set()
    
    # --- Step 1: Identify and Redact Standalone PII ---
    standalone_pii_handlers = {
        'phone': (PHONE_REGEX, redact_phone),
        'aadhar': (AADHAR_REGEX, redact_aadhar),
        'passport': (PASSPORT_REGEX, redact_name),
        'upi_id': (UPI_REGEX, redact_upi)
    }

    for key, (regex, redactor) in standalone_pii_handlers.items():
        if key in data and isinstance(data[key], str) and regex.search(data[key]):
            is_pii = True
            found_pii_types.add(key)
            redacted_data[key] = redactor(data[key])
    
    # --- Step 2: Identify Potential Combinatorial PII ---
    combinatorial_pii_found = set()
    
    # Check for name (full name with space or first+last combination)
    has_name = False
    if 'name' in data and isinstance(data['name'], str) and ' ' in data['name'].strip():
        has_name = True
        combinatorial_pii_found.add('name')
    elif ('first_name' in data and data['first_name']) and ('last_name' in data and data['last_name']):
        has_name = True
        combinatorial_pii_found.add('name')
    
    # Check for email
    has_email = 'email' in data and isinstance(data['email'], str) and EMAIL_REGEX.search(data['email'])
    if has_email:
        combinatorial_pii_found.add('email')
    
    # Check for address (look for address field with indicators)
    has_address = False
    if 'address' in data and isinstance(data['address'], str):
        # Simple check for address indicators
        address_lower = data['address'].lower()
        if any(indicator in address_lower for indicator in ADDRESS_INDICATORS):
            has_address = True
            combinatorial_pii_found.add('address')
    
    # Check for device/IP identifiers
    has_device_id = 'device_id' in data and data['device_id']
    has_ip = 'ip_address' in data and isinstance(data['ip_address'], str) and IPV4_REGEX.search(data['ip_address'])
    
    if has_device_id or has_ip:
        combinatorial_pii_found.add('device_ip')
    
    # --- Step 3: Check Combinatorial Condition and Redact ---
    if len(combinatorial_pii_found) >= 2:
        is_pii = True
        
        # Redact all identified combinatorial PII fields
        if 'name' in combinatorial_pii_found:
            if 'name' in data:
                redacted_data['name'] = redact_name(data['name'])
            if 'first_name' in data:
                redacted_data['first_name'] = redact_name(data['first_name'])
            if 'last_name' in data:
                redacted_data['last_name'] = redact_name(data['last_name'])
        
        if 'email' in combinatorial_pii_found:
            redacted_data['email'] = redact_email(data['email'])
        
        if 'address' in combinatorial_pii_found:
            redacted_data['address'] = redact_address(data['address'])
        
        if 'device_ip' in combinatorial_pii_found:
            if 'device_id' in data:
                redacted_data['device_id'] = f"[REDACTED_DEVICE_ID]"
            if 'ip_address' in data:
                redacted_data['ip_address'] = redact_ip(data['ip_address'])
    
    return redacted_data, is_pii


def main(input_file: str, output_file: str):
    """
    Main function to read, process, and write the CSV data.
    """
    try:
        with open(input_file, mode='r', encoding='utf-8') as infile, \
             open(output_file, mode='w', encoding='utf-8', newline='') as outfile:
            
            reader = csv.DictReader(infile)
            writer = csv.writer(outfile)
            
            # Write header for the output file
            writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])
            
            print(f"Processing {input_file}...")

            for row in reader:
                record_id = row['record_id']
                data_json_str = row['data_json']
                
                try:
                    # Parse the JSON data
                    data = json.loads(data_json_str)
                    
                    redacted_data, is_pii = process_record(data)
                    
                    # Convert the redacted dictionary back to a JSON string
                    redacted_json_str = json.dumps(redacted_data)
                    
                    writer.writerow([record_id, redacted_json_str, is_pii])

                except json.JSONDecodeError:
                    print(f"Warning: Could not decode JSON for record_id {record_id}. Skipping.")
                    writer.writerow([record_id, data_json_str, False])
                except Exception as e:
                    print(f"An error occurred at record_id {record_id}: {e}")
                    writer.writerow([record_id, data_json_str, False])

            print(f"Processing complete. Output written to {output_file}.")

    except FileNotFoundError:
        print(f"Error: Input file not found at {input_file}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_saumya_seetha.py <input_csv_file>")
        sys.exit(1)
        
    input_csv = sys.argv[1]
    output_csv = "redacted_output_saumya_seetha.csv"
    
    main(input_csv, output_csv)