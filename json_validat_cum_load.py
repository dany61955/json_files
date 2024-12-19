import json
import sys

def validate_json_file(file_path):
    """
    Validates the JSON file for parsing errors, warnings, and errors.
    Displays all issues, including line numbers, and stops further processing if any are found.
    """
    try:
        # Read the raw JSON content
        with open(file_path, 'r') as file:
            raw_content = file.read()
        
        # Parse the JSON content
        data = json.loads(raw_content)
    except json.JSONDecodeError as e:
        # Display JSON parsing error with line and column info
        print(f"JSON parsing error at line {e.lineno}, column {e.colno}: {e.msg}")
        sys.exit(1)

    # Initialize issue counters
    warnings_found = data.get("warnings", [])
    errors_found = data.get("errors", [])

    # If warnings or errors exist, display them with their details
    if warnings_found or errors_found:
        print("\nValidation failed. Issues found in the JSON file:\n")
        if warnings_found:
            print("Warnings:")
            for idx, warning in enumerate(warnings_found, 1):
                print(f"{idx}. {warning}")
        if errors_found:
            print("\nErrors:")
            for idx, error in enumerate(errors_found, 1):
                print(f"{idx}. {error}")

        # Highlight line numbers where warnings/errors may occur (if retrievable)
        print("\nTip: Check the provided JSON for these issues.")
        sys.exit(1)

    print("JSON validation passed. No warnings or errors found.")
    return data

def main():
    # File path for the JSON file
    json_file_path = "input.json"  # Replace with your actual file path

    # Validate JSON file
    validated_data = validate_json_file(json_file_path)

    # Process the validated JSON data
    print("Processing JSON data...")
    print(json.dumps(validated_data, indent=4))

if __name__ == "__main__":
    main()
