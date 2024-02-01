import nbformat
import uuid
from nbconvert.preprocessors import ExecutePreprocessor
import os
os.environ['PYDEVD_DISABLE_FILE_VALIDATION'] = '1'

def run_notebook_and_extract_fp(notebook_path, feature=None):
    # Load the notebook
    with open(notebook_path, 'r', encoding='utf-8') as f:
        notebook_content = f.read()
    
    # Parse the notebook content
    notebook = nbformat.reads(notebook_content, as_version=4)
    #validate notebook


    # Modify the feature_to_drop cell if a feature is provided
    if feature:
        for cell in notebook.cells:
            if cell.source.startswith("feature_to_drop"):
                cell.source = f'feature_to_drop = "{feature}"'
                break

    # Execute the notebook
    ep = ExecutePreprocessor(timeout=600, kernel_name='python3')
    ep.preprocess(notebook, {'metadata': {'path': './'}})

    # Extract the false positives value
    # Assuming the last cell contains the value we want to extract
    last_cell_output = notebook.cells[-1].outputs[0].text
    return int(last_cell_output)  # Assuming false positives value is an integer

# List of features to drop
features_to_drop = ['lex_phishing_tetragram_matches', 'rdap_ip_v4_count', 'lex_ipv4_in_domain', 'rdap_domain_active_time', 'dns_zone_entropy']  

# Execute the notebook for the first time without dropping any feature
initial_fp_value = run_notebook_and_extract_fp('Playground.ipynb')

# Execute the notebook for each feature
for feature in features_to_drop:
    fp_value = run_notebook_and_extract_fp('Playground.ipynb', feature)
    # Calculate the percentage change in false positives
    percentage_change = ((fp_value - initial_fp_value) / initial_fp_value) * 100
    
    # Determine whether the false positives increased or decreased
    change_direction = "increased" if percentage_change > 0 else "decreased"
    
    # Build and print the message
    message = f"After dropping {feature} feature, the amount of FP {change_direction} by {abs(percentage_change):.2f}%. The new FP value is {fp_value}"
    print(message)
