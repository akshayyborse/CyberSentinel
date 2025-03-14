from cybersentinel import CyberSentinel
import numpy as np
import time

def main():
    print("Initializing CyberSentinel 2025...")
    sentinel = CyberSentinel()
    
    print("\nSimulating network traffic analysis...")
    # Create more realistic sample traffic data
    sample_traffic = np.random.rand(1, 100)
    
    # Add a progress indicator
    print("Scanning network traffic", end="")
    for _ in range(3):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print("\n")
    
    # Scan for threats
    results = sentinel.scan_network_traffic(sample_traffic)
    
    # Format the output
    print("=" * 50)
    print("SCAN RESULTS:")
    print("=" * 50)
    if isinstance(results, list):
        print("\nTHREAT DETECTED! Countermeasures initiated:")
        for action in results:
            print(f"✓ {action}")
    else:
        print("\n✓ " + results)
    print("=" * 50)

if __name__ == "__main__":
    main() 