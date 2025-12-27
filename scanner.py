import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                print(f"Port {port} is OPEN")
                return port
    except Exception:
        pass
    return None

def main():
    target = input("Enter target IP or hostname: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    
    print(f"Scanning {target} from port {start_port} to {end_port}...")
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        ports = range(start_port, end_port + 1)
        results = list(executor.map(lambda p: scan_port(target, p), ports))
    
    open_ports = [p for p in results if p is not None]
    print(f"\nScan complete. Open ports: {open_ports}")

if __name__ == "__main__":
    main()
