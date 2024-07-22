import json
import re

def scrub_sensitive_data(terraform_plan_file):
    # Define patterns for sensitive data and domains
    sensitive_patterns = {
        "aws_access_key": re.compile(r'(?<=aws_access_key\s*=\s*")[^"]+'),
        "aws_secret_key": re.compile(r'(?<=aws_secret_key\s*=\s*")[^"]+'),
        "password": re.compile(r'(?<=password\s*=\s*")[^"]+'),
        "private_key": re.compile(r'(?<=private_key\s*=\s*")[^"]+'),
        "token": re.compile(r'(?<=token\s*=\s*")[^"]+'),
        "domain": re.compile(r'([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})')
    }

    with open(terraform_plan_file, 'r') as file:
        data = json.load(file)

    def scrub(value):
        if isinstance(value, str):
            for key, pattern in sensitive_patterns.items():
                value = pattern.sub('<REDACTED>', value)
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

    print(f"Sensitive data and domain names in {terraform_plan_file} have been scrubbed.")

# Example usage
scrub_sensitive_data('your_terraform_plan.json')
