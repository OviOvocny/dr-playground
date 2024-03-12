#!/bin/bash

# Check if a rule file argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: ./domain_filter.sh <rule_file>"
    exit 1
fi

rule_file="$1"
if [ ! -f "$rule_file" ]; then
    echo "Rule file does not exist: $rule_file"
    exit 2
fi

# Prepare the filtered.out file by clearing its contents or creating it if it does not exist
> filtered.out

# Read from stdin line by line
while IFS= read -r line; do
    match_found=0
    # Read each rule from the rule file
    while IFS= read -r rule; do
        # Skip empty lines and lines starting with #
        if [[ -z "$rule" ]] || [[ "$rule" == \#* ]]; then
            continue
        fi

        # Check if the line matches the current rule
        if [[ $line =~ $rule ]]; then
            # Write the line to filtered.out if a match is found
            echo "$line" >> filtered.out
            match_found=1
            break # No need to check other rules if a match is found
        fi
    done < "$rule_file"
    
    # If no match was found, print the line to stdout
    if [ "$match_found" -eq 0 ]; then
        echo "$line"
    fi
done

# If the script is run without a pipe to provide stdin, this message guides the user.
if [ -t 0 ]; then
    echo "Please provide input through stdin. For example:"
    echo "cat your_input_file | ./domain_filter.sh $rule_file"
fi

