import time
import os
import json
import subprocess
import sys
from datetime import datetime

def check_build_mode(build_dir):
    """Checks if the project was built in Release mode by inspecting CMakeCache.txt."""
    cache_file = os.path.join(build_dir, "CMakeCache.txt")
    
    if not os.path.exists(cache_file):
        print(f"[Error] Cannot find {cache_file}. Please build the project first.")
        return False
    
    with open(cache_file, 'r') as f:
        content = f.read()
        # Look for CMAKE_BUILD_TYPE:STRING=Release
        if "CMAKE_BUILD_TYPE:STRING=Release" in content:
            return True
    return False

def run_batch():
    # --- Added Build Mode Check ---
    build_directory = "./build"
    if not check_build_mode(build_directory):
        print("************************************************************")
        print("[ERROR] The project is NOT built in Release mode.")
        print("Please rebuild with: cmake -DCMAKE_BUILD_TYPE=Release ..")
        print("************************************************************")
        sys.exit(1) # Exit the script with error code
    # ------------------------------

    # 1. Search for target experiment directories
    config_dirs = [d for d in os.listdir('.') if os.path.isdir(d) and d.startswith('config_')]
    
    # List of max_concurrency levels to use in experiments
    concurrency_levels = [32, 16, 8, 4, 2, 1]
    
    # Executable program name
    executable = "./build/_deps/fpnt-build/standalone/fpnt" 
    
    # Summary result filename (CSV format)
    summary_file = "batch_fpnt_result.txt"

    # Create file and write header if it doesn't exist
    if not os.path.exists(summary_file):
        with open(summary_file, 'w', encoding='utf-8') as res_f:
            res_f.write("exp_name,max_concurrency,start_time,end_time,duration_sec,return_code\n")

    for config_dir in config_dirs:
        exp_name = config_dir.split('_', 1)[1]
        source_json = f"config_{exp_name}.json"
        
        if not os.path.exists(source_json):
            print(f"[Warning] Skipping experiment {exp_name}: {source_json} not found.")
            continue

        print(f"\n>>> Starting Experiment: {exp_name}")

        with open(source_json, 'r') as f:
            base_config = json.load(f)

        for mc in concurrency_levels:
            multiprocessing_val = mc > 1
            original_output_path = base_config.get("output_path", "output")
            trial_output_path = f"{original_output_path}_{mc}"
            
            # Update and save configuration
            trial_config = base_config.copy()
            trial_config["max_concurrency"] = mc
            trial_config["multiprocessing"] = multiprocessing_val
            trial_config["output_path"] = trial_output_path

            with open("config.json", 'w') as f:
                json.dump(trial_config, f, indent=4)

            print(f"  [Trial] {exp_name} (MC={mc}) -> {trial_output_path}")

            # Log dump filename
            dump_filename = f"batch_fpnt_dump_{exp_name}_{mc}.txt"
            
            # Measure start time
            start_time = time.time()
            start_dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            try:
                with open(dump_filename, 'w', encoding='utf-8') as dump_f:
                    process = subprocess.Popen(
                        [executable],
                        cwd=os.getcwd(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding='utf-8'
                    )

                    # Read and save stdout in real-time
                    while True:
                        output = process.stdout.readline()
                        if output == '':
                            break
                        print(output.strip())
                        dump_f.write(output.strip() + "\n")
                        dump_f.flush()

                    process.wait()

                # Measure end time
                end_time = time.time()
                end_dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                duration = round(end_time - start_time, 2)

                # Write CSV line (comma-separated)
                result_line = f"{exp_name},{mc},{start_dt},{end_dt},{duration},{process.returncode}\n"
                
                with open(summary_file, 'a', encoding='utf-8') as res_f:
                    res_f.write(result_line)

                print(f"  [Completed] Duration: {duration}s (Exit Code: {process.returncode})")
                time.sleep(10)  # Waiting time before next trial
                    
            except Exception as e:
                print(f"  [Failed] Exception occurred: {e}")
                # Record error in summary file even if exception occurs
                with open(summary_file, 'a', encoding='utf-8') as res_f:
                    res_f.write(f"{exp_name},{mc},{start_dt},ERROR,{round(time.time()-start_time,2)},-1\n")

if __name__ == "__main__":
    run_batch()