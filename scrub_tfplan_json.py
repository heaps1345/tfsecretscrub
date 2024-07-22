import json
import re

def scrub_sensitive_data(terraform_plan_file):
    # Define patterns for sensitive data, domains, IP addresses, AWS ARNs, Akamai zone IDs, SSH public keys, UUIDs, rtb-, and dxvif-
    sensitive_patterns = {
        "aws_access_key": re.compile(r'aws_access_key\s*=\s*".*?"'),
        "aws_secret_key": re.compile(r'aws_secret_key\s*=\s*".*?"'),
        "password": re.compile(r'password\s*=\s*".*?"'),
        "private_key": re.compile(r'private_key\s*=\s*".*?"'),
        "token": re.compile(r'token\s*=\s*".*?"'),
        "domain": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b'),
        "ip_address": re.compile(r'\b\d{1,3}(\.\d{1,3}){3}\b'),
        "aws_arn": re.compile(r'arn:aws:iam::\d{12}:'),
        "akamai_zone_id": re.compile(r'akamai_zone_id\s*=\s*".*?"'),
        "ssh_public_key": re.compile(r'ssh-rsa\s+[^"]+'),
        "uuid": re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'),
        "rtb": re.compile(r'\brtb-[a-zA-Z0-9]{7}\b'),
        "dxvif": re.compile(r'\bdxvif-[a-zA-Z0-9]{6}\b')
    }

    with open(terraform_plan_file, 'r') as file:
        data = json.load(file)

    def scrub(value):
        if isinstance(value, str):
            for key, pattern in sensitive_patterns.items():
                value = pattern.sub(f'{key}="<REDACTED>"', value)
        return value

    def traverse_and_scrub(obj):
        if isinstance(obj, dict):
            return {k: traverse_and_scrub(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [traverse_and_scrub(elem) for elem in obj]
        else:
            return scrub(obj)

    scrubbed_data = traverse_and_scrub(data)

    with open(terraform_plan_file, 'w') as file:
        json.dump(scrubbed_data, file, indent=2)

    print(f"Sensitive data, domain names, IP addresses, AWS ARNs, Akamai zone IDs, SSH public keys, UUIDs, and values beginning with rtb- and dxvif- in {terraform_plan_file} have been scrubbed.")

# Example usage
scrub_sensitive_data('tfplan.json')
