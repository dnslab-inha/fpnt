import time
import os
import json
import subprocess
import sys
import psutil
import matplotlib.pyplot as plt
from datetime import datetime

# Note: to use this script, you need to install psutil and matplotlib
# pip install psutil matplotlib

# --- Settings ---
SAMPLING_INTERVAL = 0.2  # 샘플링 간격 (초 단위)
CHECK_RELEASE_MODE = True # 빌드 모드 체크 여부
concurrency_levels = [64, 32, 16, 8, 4, 2, 1]
executable = "./build/standalone/fpnt" 
summary_file = "./batch_fpnt_result.txt"
batch_fpnt_dumpfile_prefix = "./batch_fpnt_dump"
memory_footprint_logfile_prefix = "./memory_footprint"
MOVING_AVERAGE_WINDOW = 5 # 이동 평균 윈도우 설정

def call_external_plot(mem_log_filename):
    """외부 파이썬 스크립트를 호출하여 그래프 생성"""
    try:
        subprocess.run([
            sys.executable, "plot_memory_footprint.py", 
            mem_log_filename, str(MOVING_AVERAGE_WINDOW)
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"  [Error] Failed to generate plot via script: {e}")

def check_build_mode(build_dir):
    """Checks if the project was built in Release mode by inspecting CMakeCache.txt."""
    cache_file = os.path.join(build_dir, "CMakeCache.txt")
    if not os.path.exists(cache_file):
        print(f"[Error] Cannot find {cache_file}. Please build the project first.")
        return False
    with open(cache_file, 'r') as f:
        content = f.read()
        if "CMAKE_BUILD_TYPE:STRING=Release" in content:
            return True
    return False

def get_tree_memory(parent_pid):
    """Calculates total RSS memory (MB) of a process and all its children."""
    try:
        parent = psutil.Process(parent_pid)
        processes = [parent] + parent.children(recursive=True)
        total_mem = 0
        for p in processes:
            try:
                total_mem += p.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return total_mem / (1024 * 1024)  # Convert to MB
    except psutil.NoSuchProcess:
        return 0

def save_memory_plot(timestamps, mem_usages, exp_name, mc):
    """Generates and saves a memory usage plot."""
    plt.figure(figsize=(10, 6))
    plt.plot(timestamps, mem_usages, label='Total RSS Memory', color='blue')
    plt.fill_between(timestamps, mem_usages, color='blue', alpha=0.1)
    plt.xlabel('Time (seconds)')
    plt.ylabel('Memory Usage (MB)')
    plt.title(f'Memory Footprint: {exp_name} (MC={mc})')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    
    plot_filename = f"memory_plot_{exp_name}_{mc}.png"
    plt.savefig(plot_filename)
    plt.close()
    print(f"  [Info] Memory plot saved as {plot_filename}")

def run_batch():
    build_directory = "./build"
    if CHECK_RELEASE_MODE and not check_build_mode(build_directory):
        print("************************************************************")
        print("[ERROR] The project is NOT built in Release mode.")
        print("Please rebuild with: cmake -DCMAKE_BUILD_TYPE=Release ..")
        print("************************************************************")
        sys.exit(1)

    config_dirs = [d for d in os.listdir('.') if os.path.isdir(d) and d.startswith('config_')]

    if not os.path.exists(summary_file):
        with open(summary_file, 'w', encoding='utf-8') as res_f:
            res_f.write("exp_name,max_concurrency,start_time,end_time,duration_sec,max_memory_mb,return_code\n")

    for config_dir in config_dirs:
        exp_name = config_dir.split('_', 1)[1]
        source_json = f"config_{exp_name}.json"
        
        if not os.path.exists(source_json):
            print(f"[Warning] Skipping {exp_name}: {source_json} not found.")
            continue

        with open(source_json, 'r') as f:
            base_config = json.load(f)

        for mc in concurrency_levels:
            multiprocessing_val = mc > 1
            trial_output_path = f"{base_config.get('output_path', 'output')}_{mc}"
            
            trial_config = base_config.copy()
            trial_config.update({"max_concurrency": mc, "multiprocessing": multiprocessing_val, "output_path": trial_output_path})

            with open("config.json", 'w') as f:
                json.dump(trial_config, f, indent=4)

            print(f"\n>>> [Trial] {exp_name} (MC={mc})")

            dump_filename = f"{batch_fpnt_dumpfile_prefix}_{exp_name}_{mc}.txt"
            mem_log_filename = f"{memory_footprint_logfile_prefix}_{exp_name}_{mc}.txt"
            
            timestamps = []
            mem_usages = []
            start_time = time.time()
            start_dt = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            try:
                with open(dump_filename, 'w', encoding='utf-8') as dump_f, \
                     open(mem_log_filename, 'w', encoding='utf-8') as mem_f:
                    
                    mem_f.write("elapsed_sec,total_rss_mb\n")
                    
                    process = subprocess.Popen(
                        [executable],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding='utf-8'
                    )

                    # Non-blocking stdout setup
                    os.set_blocking(process.stdout.fileno(), False)

                    while process.poll() is None:
                        # 1. Output monitoring
                        line = process.stdout.readline()
                        if line:
                            dump_f.write(line)
                        
                        # 2. Memory sampling
                        current_mem_mb = get_tree_memory(process.pid)
                        elapsed = time.time() - start_time
                        
                        timestamps.append(elapsed)
                        mem_usages.append(current_mem_mb)
                        
                        mem_f.write(f"{round(elapsed, 2)},{round(current_mem_mb, 2)}\n")
                        
                        time.sleep(SAMPLING_INTERVAL)

                    process.wait()

                    # [실행부 내부의 데이터 수집 완료 후]
                    duration = round(time.time() - start_time, 2)
                    max_mem_mb = round(max(mem_usages), 2) if mem_usages else 0
                    
                    result_line = f"{exp_name},{mc},{start_dt},{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},{duration},{max_mem_mb},{process.returncode}\n"
                    with open(summary_file, 'a', encoding='utf-8') as res_f:
                        res_f.write(result_line)

                    # 내부 함수 대신 외부 스크립트 호출
                    call_external_plot(mem_log_filename)

                    print(f"  [Completed] Time: {duration}s | Max Mem: {max_mem_mb} MB")
                    time.sleep(5)
                    
            except Exception as e:
                print(f"  [Failed] Exception: {e}")
                with open(summary_file, 'a', encoding='utf-8') as res_f:
                    res_f.write(f"{exp_name},{mc},{start_dt},ERROR,{round(time.time()-start_time,2)},0,-1\n")

if __name__ == "__main__":
    run_batch()