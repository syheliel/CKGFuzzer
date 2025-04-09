#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status.

# Get the full path to the script
script_path=$(realpath "$0")

# Extract the directory path
script_dir=$(dirname "$script_path")
cd "$script_dir"

fn_name=$1
fn_file=$2
fn_file="${fn_file//\//_}"
dbbase=$3
outputfolder=$4
pid=$5

echo "Database ====== $script_dir"
echo "Database path: $dbbase"
echo "Output folder: $outputfolder"
echo "Process ID: $pid"
echo "Function name: $fn_name"
echo "File name: $fn_file"

# Check if the database exists
if [ ! -d "$dbbase" ]; then
    echo "Error: Database directory does not exist: $dbbase"
    exit 1
fi

# Check if the output folder exists
if [ ! -d "$outputfolder" ]; then
    echo "Error: Output folder does not exist: $outputfolder"
    exit 1
fi

[ -d "$outputfolder/call_graph" ] || mkdir -p "$outputfolder/call_graph"
outputfile="$outputfolder/call_graph/${fn_file}@${fn_name}_call_graph.bqrs"
QUERY_TEMPLATE="./extract_call_graph_template.ql"
QUERY="call_graph_${pid}.ql"

# Check if the template file exists
if [ ! -f "$QUERY_TEMPLATE" ]; then
    echo "Error: Query template file does not exist: $QUERY_TEMPLATE"
    exit 1
fi

echo "Copying template and generating query file..."
cp "$QUERY_TEMPLATE" "$QUERY"
sed -i "s/ENTRY_FNC/$fn_name/g" "$QUERY"

# Check if the query file was created
if [ ! -f "$QUERY" ]; then
    echo "Error: Failed to create query file: $QUERY"
    exit 1
fi

echo "Running query: codeql query run $QUERY --database=$dbbase --output=$outputfile"
if codeql query run "$QUERY" --database="$dbbase" --output="$outputfile"; then
    echo "Query executed successfully. Converting BQRS to CSV."
    csv_output="${outputfile%.bqrs}.csv"
    if codeql bqrs decode --format=csv "$outputfile" --output="$csv_output"; then
        echo "BQRS file successfully converted to CSV: $csv_output"
    else
        echo "Error converting BQRS to CSV"
        exit 1
    fi
else
    echo "Error executing CodeQL query"
    exit 1
fi

# Clean up the temporary query file
rm "$QUERY"