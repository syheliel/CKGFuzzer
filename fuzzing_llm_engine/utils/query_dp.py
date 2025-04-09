from loguru import logger
import subprocess
from . import _get_command_string
import os
from configs.codeql_config import CODEQL_PATH
from pathlib import Path
def add_codeql_to_path():
    codeql_path = CODEQL_PATH
    current_path = os.environ.get('PATH', '')

    # Check if CodeQL path is already in PATH
    if codeql_path not in current_path:
        # Adding CodeQL to PATH
        os.environ['PATH'] += os.pathsep + codeql_path
        print(f"CodeQL has been added to PATH. New PATH: {os.environ['PATH']}")
    else:
        print("CodeQL is already in the PATH.")

add_codeql_to_path()


def run_command(command):
    try:
        logger.info(f"Running command: {' '.join(command)}")
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        
        # Log the output regardless of success
        if result.stdout:
            logger.info(f"Command stdout: {result.stdout}")
        if result.stderr:
            logger.error(f"Command stderr: {result.stderr}")
        
        # Check if the command was successful
        if result.returncode != 0:
            logger.error(f"Command failed with exit code {result.returncode}")
            return ""
            
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run the query: {e}")
        if e.stderr:
            logger.error(f"Command stderr: {e.stderr.decode() if isinstance(e.stderr, bytes) else e.stderr}")
        return ""
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return ""
    

def run_converted_csv(output_file:str) -> str:
    # codeql bqrs decode --format=csv ./find_api.bqrs  --output=find_api.csv
    csv_file = output_file.replace('.bqrs', '.csv')
    output_file_path = Path(output_file).resolve()
    
    # Check if the BQRS file exists
    if not output_file_path.exists():
        logger.error(f"BQRS file does not exist: {output_file}")
        return csv_file
        
    output_file_path.parent.mkdir(parents=True, exist_ok=True)
    command = [ "codeql", "bqrs", "decode", "--format=csv", output_file, f"--output={csv_file}" ]
    logger.info(f'Running: {_get_command_string(command)}' )
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        
        # Log the output regardless of success
        if result.stdout:
            logger.info(f"Command stdout: {result.stdout}")
        if result.stderr:
            logger.error(f"Command stderr: {result.stderr}")
        
        # Check if the command was successful
        if result.returncode != 0:
            logger.error(f"Command failed with exit code {result.returncode}")
            return csv_file
            
        return csv_file
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run the query: {e}")
        if e.stderr:
            logger.error(f"Command stderr: {e.stderr.decode() if isinstance(e.stderr, bytes) else e.stderr}")
        return csv_file
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return csv_file

def run_query(query_script, output_file, database_db: str, additional_options=None) -> str:
    """
    Run the provided query on the database and return the results.

    Args:
        query (str): Query to be run on the database.
        database_db (str): Path to the database.

    Returns:
        str: Results of the query.
    """
    # Construct the command to run the query
    logger.info(f"CodeQL Path: {os.environ['PATH']}")
    command =[ "codeql", "query", "run", query_script, "-d", database_db, f"--output={output_file}" ]
    #command =[ "/home/mawei/Desktop/work1/wei/fuzzing_llm/fuzzing_os/oss-fuzz-modified/docker_shared/codeql/codeql", "--license" ]
    if additional_options:
        command += ["--additional_options", additional_options]
    logger.info(f'Running: %s {_get_command_string(command)}' )
    print(" ".join(command))
    try:
        subprocess.run(command, check=True, text=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run the query: {e}")
        return ""
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return ""