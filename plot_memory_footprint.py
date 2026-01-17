import pandas as pd
import matplotlib.pyplot as plt
import sys
import os

def generate_plot(csv_file, window_size=5):
    if not os.path.exists(csv_file):
        print(f"[Error] File not found: {csv_file}")
        return

    # 데이터 읽기 (elapsed_sec, total_rss_mb)
    try:
        df = pd.read_csv(csv_file)
        if df.empty:
            print(f"[Warning] {csv_file} is empty.")
            return
    except Exception as e:
        print(f"[Error] Failed to read CSV: {e}")
        return

    plt.figure(figsize=(10, 6))

    # 원본 데이터 플롯
    plt.plot(df['elapsed_sec'], df['total_rss_mb'], 
             label='Raw RSS Memory', color='blue', alpha=0.3)

    # 이동 평균(Moving Average) 계산 및 플롯
    if window_size > 1:
        df['ma'] = df['total_rss_mb'].rolling(window=window_size, min_periods=1).mean()
        plt.plot(df['elapsed_sec'], df['ma'], 
                 label=f'Moving Average (w={window_size})', color='red', linewidth=2)

    plt.fill_between(df['elapsed_sec'], df['total_rss_mb'], color='blue', alpha=0.05)
    
    plt.xlabel('Time (seconds)')
    plt.ylabel('Memory Usage (MB)')
    
    # 파일명에서 제목 추출
    title = os.path.basename(csv_file).replace('.txt', '')
    plt.title(f'Memory Footprint: {title}')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    
    # 결과 이미지 저장 (텍스트 파일과 같은 이름의 png)
    output_png = csv_file.replace('.txt', '.png')
    plt.savefig(output_png)
    plt.close()
    print(f"  [Info] Plot saved as {output_png}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python plot_memory_footprint.py <csv_file> [window_size]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    window = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    generate_plot(file_path, window)