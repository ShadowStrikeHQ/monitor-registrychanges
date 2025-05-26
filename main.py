import argparse
import logging
import os
import sys
import time

try:
    import winreg
except ImportError:
    print("This script requires the 'winreg' module, which is only available on Windows.")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """Sets up the argument parser for the script."""
    parser = argparse.ArgumentParser(description="Monitors specific registry keys for modifications.")
    parser.add_argument("-k", "--key", required=True, help="The registry key to monitor (e.g., HKEY_LOCAL_MACHINE\\Software\\MyApplication)")
    parser.add_argument("-i", "--interval", type=int, default=60, help="The monitoring interval in seconds (default: 60)")
    parser.add_argument("-l", "--log", help="Path to the log file (optional)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level)")
    parser.add_argument("-o", "--output", help="Output changes to a file. Useful for offline analysis.")
    
    return parser.parse_args()

def validate_key(key_path):
    """Validates the registry key path."""
    if not isinstance(key_path, str):
        logging.error("Invalid registry key format.  Key must be a string.")
        return False
    
    if not key_path:
        logging.error("Registry key cannot be empty.")
        return False
    
    # Add more validation here if needed (e.g., check valid hive names)
    return True


def get_registry_key_values(key_path):
    """
    Retrieves the values of a registry key.

    Args:
        key_path (str): The path to the registry key.

    Returns:
        dict: A dictionary where keys are value names and values are value data.
        Returns None if the key does not exist or if an error occurs.
    """
    try:
        # Determine the hive based on the key path
        if key_path.startswith("HKEY_LOCAL_MACHINE"):
            hive = winreg.HKEY_LOCAL_MACHINE
            sub_key = key_path[len("HKEY_LOCAL_MACHINE\\"):]
        elif key_path.startswith("HKEY_CURRENT_USER"):
            hive = winreg.HKEY_CURRENT_USER
            sub_key = key_path[len("HKEY_CURRENT_USER\\"):]
        elif key_path.startswith("HKEY_CLASSES_ROOT"):
            hive = winreg.HKEY_CLASSES_ROOT
            sub_key = key_path[len("HKEY_CLASSES_ROOT\\"):]
        elif key_path.startswith("HKEY_USERS"):
            hive = winreg.HKEY_USERS
            sub_key = key_path[len("HKEY_USERS\\"):]
        elif key_path.startswith("HKEY_CURRENT_CONFIG"):
            hive = winreg.HKEY_CURRENT_CONFIG
            sub_key = key_path[len("HKEY_CURRENT_CONFIG\\"):]
        else:
            logging.error("Invalid registry hive. Supported hives are: HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT, HKEY_USERS, HKEY_CURRENT_CONFIG")
            return None
            
        # Open the registry key
        try:
            key = winreg.OpenKey(hive, sub_key)
        except FileNotFoundError:
            logging.error(f"Registry key '{key_path}' not found.")
            return None
        except Exception as e:
            logging.error(f"Error opening registry key '{key_path}': {e}")
            return None

        values = {}
        i = 0
        while True:
            try:
                name, value, value_type = winreg.EnumValue(key, i)
                values[name] = (value, value_type) # Store value and its type
                i += 1
            except OSError:
                # No more values
                break

        winreg.CloseKey(key)
        return values

    except Exception as e:
        logging.error(f"Error retrieving registry key values for '{key_path}': {e}")
        return None


def compare_registry_values(old_values, new_values, key_path):
    """
    Compares two sets of registry values and returns the differences.

    Args:
        old_values (dict): The previous registry values.
        new_values (dict): The current registry values.
        key_path (str): The registry key path being monitored.

    Returns:
        dict: A dictionary containing the changes (added, modified, removed).
    """
    changes = {"added": [], "modified": [], "removed": []}

    if old_values is None and new_values is None:
        return changes # No changes if both are None
    
    if old_values is None:
        changes["added"] = list(new_values.keys())
        return changes

    if new_values is None:
        changes["removed"] = list(old_values.keys())
        return changes

    # Check for added values
    for name, value_data in new_values.items():
        if name not in old_values:
            changes["added"].append(name)

    # Check for removed values
    for name in old_values.keys():
        if name not in new_values:
            changes["removed"].append(name)

    # Check for modified values
    for name, value_data in new_values.items():
        if name in old_values:
            old_value, old_type = old_values[name]
            new_value, new_type = value_data

            if old_value != new_value or old_type != new_type:
                changes["modified"].append(name)

    return changes


def log_changes(changes, key_path, output_file=None):
    """Logs the detected changes to the console and/or a file."""
    if changes["added"]:
        logging.info(f"Registry key '{key_path}': Added values - {changes['added']}")
        if output_file:
            with open(output_file, "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Registry key '{key_path}': Added values - {changes['added']}\n")
    if changes["modified"]:
        logging.info(f"Registry key '{key_path}': Modified values - {changes['modified']}")
        if output_file:
            with open(output_file, "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Registry key '{key_path}': Modified values - {changes['modified']}\n")
    if changes["removed"]:
        logging.info(f"Registry key '{key_path}': Removed values - {changes['removed']}")
        if output_file:
            with open(output_file, "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Registry key '{key_path}': Removed values - {changes['removed']}\n")


def main():
    """Main function to monitor the registry key."""
    args = setup_argparse()

    if args.log:
        # Configure logging to file if specified
        file_handler = logging.FileHandler(args.log)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    key_path = args.key
    interval = args.interval
    output_file = args.output

    if not validate_key(key_path):
        sys.exit(1)

    # Get initial registry values
    old_values = get_registry_key_values(key_path)
    if old_values is None:
        logging.warning(f"Could not retrieve initial values for '{key_path}'. Monitoring will continue, but no initial comparison can be made.")
    else:
        logging.debug(f"Successfully retrieved initial values for '{key_path}'.")
    

    try:
        while True:
            # Get current registry values
            new_values = get_registry_key_values(key_path)
            
            # Compare values and log changes
            if old_values is not None or new_values is not None: # Only compare if we had at least one successful read
                changes = compare_registry_values(old_values, new_values, key_path)
                log_changes(changes, key_path, output_file)
            else:
                logging.warning(f"Skipping comparison because previous and current registry reads failed.")


            # Update old values for the next iteration
            old_values = new_values
            
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()

# Example Usage:
# python monitor-registrychanges.py -k "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" -i 60 -l registry_monitor.log -v
# python monitor-registrychanges.py -k "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" -i 30 -o changes.txt