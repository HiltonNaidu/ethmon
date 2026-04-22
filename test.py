from core.scanner import run_scan 

if __name__ == "__main__":
    # Simple test to verify scanner is working
    print("Running test scan...")
    results = run_scan()
    print(f"Scan complete. Found {len(results.devices)} devices:")
    for device in results.devices:
        print(f" - {device.ip} ({device.mac}) [{device.hostname}]")