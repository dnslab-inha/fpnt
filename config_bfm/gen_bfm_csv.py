import argparse
import csv
import sys
import re

# Description for command-line arguments
DESCRIPTION = (
    "Generates new CSV content by iterating and inserting new values into specific rows of an input CSV file. "
    "Specifies the start and end integer range and the repetition type. Now modifies columns 1, 2, and 4."
)

def generate_csv_content(input_data, start_val, end_val, repeat_type):
    """
    Generates new CSV content based on the given CSV text, start/end value range, and repetition type.

    Args:
        input_data (str): The content of the input CSV file (text).
        start_val (int): The starting value of the iteration range (inclusive).
        end_val (int): The ending value of the iteration range (inclusive).
        repeat_type (int): The type of repetition (0: Integer-first, 1: Row-first).

    Returns:
        str: The generated new CSV file content.
    """
    lines = input_data.strip().split('\n')
    output_lines = []
    
    # The new pattern for the first column is "SCIDX: -122,φ11"
    # The prefix to identify the target row is now "SCIDX: " followed by a number
    TARGET_PREFIX_IDENTIFIER = "SCIDX: "
    
    # Pattern to find and replace the number part in the target columns (1, 2, and 4).
    # This pattern is more flexible to handle both "NUMBER,REST" and "SCIDX: NUMBER,REST" forms
    # For Column 1: "SCIDX: -122,φ11" -> Prefix + (NUMBER)(,REST)
    # For Columns 2 & 4: "-122,φ11" -> (NUMBER)(,REST)
    
    # Pattern for Column 1 (must include "SCIDX: ")
    NUMBER_PATTERN_COL1 = re.compile(r'^(SCIDX: -?\d+)(,.*)$') 
    # The part to substitute in Col 1 is "SCIDX: -122"
    COL1_SUB_PATTERN = re.compile(r'^(SCIDX: )(-?\d+)(,.*)$') # Group 1: "SCIDX: ", Group 2: "-122", Group 3: ",φ11"

    # Pattern for Columns 2 and 4 (must be just the number at the start)
    COL2_COL4_SUB_PATTERN = re.compile(r'^(-?\d+)(,.*)$') # Group 1: "-122", Group 2: ",φ11"


    # Identify and separate target rows from non-target rows
    target_rows = []
    non_target_lines = []
    
    for line in lines:
        # Use a more robust check: does the first column *contain* the target prefix?
        # We need to parse the first column value to check its pattern.
        
        is_target = False
        parsed_row = None
        
        try:
            # Parse the row using csv.reader
            parsed_row = next(csv.reader([line])) 
            if parsed_row[0].startswith(TARGET_PREFIX_IDENTIFIER):
                 # Check if the first column matches the expected structure to replace the number
                if COL1_SUB_PATTERN.match(parsed_row[0]):
                    is_target = True
        except Exception as e:
            # Handle parsing errors
            print(f"Warning: CSV parsing error occurred - line: '{line}', error: {e}", file=sys.stderr)
            non_target_lines.append(line)
            continue
            
        if is_target:
            target_rows.append(parsed_row)
        else:
            non_target_lines.append(line)


    # --- Repetition Logic ---

    def create_new_row_string(original_row, val):
        """Helper function to substitute the number in Col 1, 2, 4 and format the row back to CSV string."""
        new_row = list(original_row)
        
        # 1. Process the FIRST column (index 0)
        match_col1 = COL1_SUB_PATTERN.match(new_row[0])
        if match_col1:
            # Group 1: "SCIDX: ", Group 3: ",φ11"
            new_row[0] = f"{match_col1.group(1)}{val}{match_col1.group(3)}"
        else:
            # Should not happen for rows in target_rows, but for safety
            print(f"Warning: Value in the first column '{new_row[0]}' does not match the expected pattern for substitution.", file=sys.stderr)

        # 2. Process the SECOND column (index 1)
        match_col2 = COL2_COL4_SUB_PATTERN.match(new_row[1])
        if match_col2:
            # Group 1: current number, Group 2: the rest (e.g., ,φ11)
            new_row[1] = f"{val}{match_col2.group(2)}"
        else:
            print(f"Warning: Value in the second column '{new_row[1]}' does not match the expected pattern for substitution.", file=sys.stderr)

        # 3. Process the FOURTH column (index 3)
        match_col4 = COL2_COL4_SUB_PATTERN.match(new_row[3])
        if match_col4:
            # Group 1: current number, Group 2: the rest (e.g., ,phi,11)
            new_row[3] = f"{val}{match_col4.group(2)}"
        else:
            print(f"Warning: Value in the fourth column '{new_row[3]}' does not match the expected pattern for substitution.", file=sys.stderr)
        
        # Convert the new row back to CSV format: '"value1","value2",...'
        return ",".join(f'"{item}"' for item in new_row)


    if repeat_type == 0:
        # Type 0: Integer-first repetition (Iterate original lines, then range for each)
        
        # We need to preserve the interleave order of non-target lines in the original file.
        current_target_index = 0
        
        for original_line in lines:
            if original_line.startswith('"SCIDX: '): 
                # Check if it was successfully parsed as a target row
                if current_target_index < len(target_rows) and original_line == ",".join(f'"{item}"' for item in target_rows[current_target_index]):
                    original_row = target_rows[current_target_index]
                    
                    # Iterate through the range for this specific row
                    for val in range(start_val, end_val + 1):
                        output_lines.append(create_new_row_string(original_row, val))
                        
                    current_target_index += 1
                # If the line started with "SCIDX: " but wasn't a valid target row, 
                # it was added to non_target_lines, so it won't be explicitly handled here.
            else:
                # Non-target line: output as is (This covers original non-target lines AND lines that failed parsing)
                # Note: This logic assumes non-target lines are exactly as they were in the input.
                output_lines.append(original_line)
                
    elif repeat_type == 1:
        # Type 1: Row-first repetition (Iterate range, then all target rows for each value)
        
        generated_content = []
        
        # Generate the main block
        for val in range(start_val, end_val + 1):
            for original_row in target_rows:
                generated_content.append(create_new_row_string(original_row, val))
        
        # Simple Type 1 Logic: All non-target lines + Generated block
        # Find the insertion point for the generated content (i.e., the first target line's position)
        
        # Find the index of the first target line in the original input
        first_target_index = -1
        for i, line in enumerate(lines):
            try:
                # Check if this line is one of the target rows
                parsed_row = next(csv.reader([line])) 
                if parsed_row in target_rows:
                    first_target_index = i
                    break
            except:
                continue

        if first_target_index != -1:
            # Insert generated content at the position of the first target line, and then 
            # skip all subsequent original target lines.
            
            # 1. Add everything before the first target line
            output_lines.extend(lines[:first_target_index])
            
            # 2. Add the generated block
            output_lines.extend(generated_content)
            
            # 3. Add everything after the last target line (skipping all original target lines)
            is_target_line = lambda line: any(line == ",".join(f'"{item}"' for item in row) for row in target_rows)
            
            # Find the index of the last target line
            last_target_index = -1
            for i in range(len(lines) - 1, -1, -1):
                 try:
                    parsed_row = next(csv.reader([lines[i]])) 
                    if parsed_row in target_rows:
                        last_target_index = i
                        break
                 except:
                    continue

            if last_target_index != -1 and last_target_index >= first_target_index:
                output_lines.extend(lines[last_target_index + 1:])
            else:
                # Fallback: if no target lines were found (which shouldn't happen if first_target_index != -1)
                output_lines.extend(lines[first_target_index:]) # Effectively adds everything after the first target line.

        else:
             # No target lines found at all. Output original content.
             output_lines.extend(lines)

    return "\n".join(output_lines)

def main():
    """Main function: parses command-line arguments and executes the CSV generation logic"""
    
    # 1. Command-line argument setup
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        '--start', 
        default=-122,
        type=int, 
        help='The starting integer for the range (inclusive).'
    )
    parser.add_argument(
        '--end', 
        default=122,
        type=int, 
        help='The ending integer for the range (inclusive).'
    )
    parser.add_argument(
        '--input_file',
        default='output_bfm_base.csv',
        type=str,
        help='Path to the input CSV file to be processed.'
    )
    parser.add_argument(
        '--output_file',
        default='output_bfm.csv',
        type=str,
        help='Path to the output CSV file where results will be saved.'
    )
    parser.add_argument(
        '--repeat_type',
        type=int,
        default=0,
        choices=[0, 1],
        help='Repetition type (0: Integer-first, 1: Row-first). Default is 0.'
    )

    args = parser.parse_args()

    # Error handling
    if args.start > args.end:
        print("Error: The start value must be less than or equal to the end value.", file=sys.stderr)
        sys.exit(1)

    # 2. Read the file
    try:
        with open(args.input_file, 'r', encoding='utf-8') as f:
            input_data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error occurred while reading file: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Generate CSV content
    try:
        new_content = generate_csv_content(input_data, args.start, args.end, args.repeat_type)
    except Exception as e:
        print(f"Error occurred while generating CSV content: {e}", file=sys.stderr)
        sys.exit(1)

    # 4. Write the file
    try:
        with open(args.output_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"CSV file successfully generated as '{args.output_file}'. (Range: {args.start} to {args.end}, Type: {args.repeat_type})")
    except Exception as e:
        print(f"Error occurred while writing file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()