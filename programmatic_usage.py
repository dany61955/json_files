#!/usr/bin/env python3

from nat_translator import NATTranslator

def convert_nat_rules(input_file: str, output_file: str):
    """
    Example of programmatic usage of the NAT converter.
    
    Args:
        input_file (str): Path to the Checkpoint NAT policy JSON file
        output_file (str): Path to save the ASA NAT rules
    """
    try:
        # Initialize the translator
        translator = NATTranslator()
        
        # Load and convert rules
        print(f"Loading Checkpoint rules from {input_file}...")
        checkpoint_rules = translator.load_checkpoint_rules(input_file)
        
        print("Converting rules to ASA format...")
        asa_rules = translator.translate_rules(checkpoint_rules)
        
        # Save the converted rules
        print(f"Saving ASA rules to {output_file}...")
        translator.save_asa_rules(asa_rules, output_file)
        
        print("Conversion completed successfully!")
        
    except Exception as e:
        print(f"Error during conversion: {e}")
        raise

if __name__ == "__main__":
    # Example usage
    convert_nat_rules('checkpoint_nat_policy.json', 'asa_nat_rules.txt') 