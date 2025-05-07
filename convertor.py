#!/usr/bin/env python3

import argparse
import sys
import logging
from datetime import datetime
from nat_translator import NATTranslator

def setup_logging():
    """Setup logging configuration"""
    log_file = f"nat_translation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Convert Checkpoint NAT rules to Cisco ASA format'
    )
    parser.add_argument(
        'nat_rules_file',
        help='Path to the Checkpoint NAT rules JSON file'
    )
    parser.add_argument(
        'objects_file',
        help='Path to the Checkpoint objects JSON file'
    )
    parser.add_argument(
        'output_file',
        help='Path to save the converted ASA rules'
    )
    return parser.parse_args()

def main():
    """Main function to handle the conversion process"""
    logger = setup_logging()
    args = parse_arguments()
    
    try:
        logger.info("Starting NAT rule conversion process")
        logger.info(f"Input files: NAT rules={args.nat_rules_file}, Objects={args.objects_file}")
        logger.info(f"Output file: {args.output_file}")
        
        # Initialize translator
        translator = NATTranslator(
            objects_file=args.objects_file,
            log_file=None  # We're handling logging in this script
        )
        
        # Load and process rules
        logger.info("Loading Checkpoint NAT rules...")
        checkpoint_rules = translator.load_checkpoint_rules(args.nat_rules_file)
        
        logger.info("Translating rules to ASA format...")
        asa_rules = translator.translate_rules(checkpoint_rules)
        
        logger.info("Saving ASA rules...")
        translator.save_asa_rules(asa_rules, args.output_file)
        
        # Print final statistics
        logger.info("\nConversion Statistics:")
        logger.info(f"Total rules processed: {translator.stats['total_rules']}")
        logger.info(f"Successfully translated: {translator.stats['successful']}")
        logger.info(f"Failed translations: {translator.stats['failed']}")
        logger.info(f"Skipped rules: {translator.stats['skipped']}")
        logger.info(f"Object resolution errors: {translator.stats['object_errors']}")
        logger.info(f"Translation errors: {translator.stats['translation_errors']}")
        
        logger.info("Conversion completed successfully")
        
    except FileNotFoundError as e:
        logger.error(f"File not found: {str(e)}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Invalid input: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 
