#!/usr/bin/env python3

from nat_translator import NATTranslator
import argparse
import sys

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Convert Checkpoint NAT rules to ASA format')
    parser.add_argument('input_file', help='Path to the Checkpoint NAT policy JSON file')
    parser.add_argument('output_file', help='Path to save the ASA NAT rules')
    
    args = parser.parse_args()
    
    try:
        # Initialize the translator
        translator = NATTranslator()
        
        # Load and convert rules
        print(f"Loading Checkpoint rules from {args.input_file}...")
        checkpoint_rules = translator.load_checkpoint_rules(args.input_file)
        
        print("Converting rules to ASA format...")
        asa_rules = translator.translate_rules(checkpoint_rules)
        
        # Save the converted rules
        print(f"Saving ASA rules to {args.output_file}...")
        translator.save_asa_rules(asa_rules, args.output_file)
        
        print("Conversion completed successfully!")
        
    except FileNotFoundError as e:
        print(f"Error: Could not find file - {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error during conversion: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 
