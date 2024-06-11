import argparse
import socket
import concurrent.futures
import nmap
import sys
from tabulate import tabulate

def print_banner():
    banner = r"""
██╗  ██╗███╗   ██╗ ██████╗  ██████╗██╗  ██╗███████╗██████╗ 
██║ ██╔╝████╗  ██║██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
█████╔╝ ██╔██╗ ██║██║   ██║██║     █████╔╝ █████╗  ██████╔╝
██╔═██╗ ██║╚██╗██║██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██║  ██╗██║ ╚████║╚██████╔╝╚██████╗██║  ██╗███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
Created by therealslimshady
https://github.com/therealslimshady0
https://x.com/dare4lslimshady
"""
    print(banner)

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            print(f"Port {port} is open")
            return port
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
    return None

def scan_ports(ip, port_range, max_workers):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in port_range}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return open_ports

def detailed_scan_port(nm, ip, port):
    nm.scan(ip, str(port))
    port_info = nm[ip]['tcp'][port]
    return [port, port_info['name'], port_info['state'], port_info['product'], port_info['version']]

def detailed_scan(ip, open_ports, max_workers):
    nm = nmap.PortScanner()
    details = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(detailed_scan_port, nm, ip, port): port for port in open_ports}
        for future in concurrent.futures.as_completed(future_to_port):
            details.append(future.result())
    return details

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="Fast port scanner with Nmap integration")
    parser.add_argument("ip", nargs='?', help="Target IP address")
    parser.add_argument("-p", "--ports", help="Port range (default 1-65535)", default="1-65535")
    parser.add_argument("-t", "--threads", help="Number of threads (default 60)", type=int, default=60)
    parser.add_argument("-d", "--detailed", help="Perform detailed scan using Nmap", action="store_true")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        print("No flags provided. Use -h for help.")
        print("\nExamples:")
        print("  python scanner.py <target_ip>")
        print("  python scanner.py <target_ip> -p 1-1000")
        print("  python scanner.py <target_ip> -t 50")
        print("  python scanner.py <target_ip> -d")
        sys.exit(1)

    if args.ip is None:
        parser.print_help()
        sys.exit(1)

    ip = args.ip
    ports = [int(p) for p in args.ports.split('-')]
    port_range = range(ports[0], ports[1] + 1)
    thread_count = args.threads

    print(f"Scanning {ip} for open ports...")
    open_ports = scan_ports(ip, port_range, thread_count)

    if open_ports:
        print(f"Open ports: {open_ports}")
        if args.detailed:
            print("Performing detailed scan...")
            details = detailed_scan(ip, open_ports, thread_count)
            print(tabulate(details, headers=["Port", "Service", "State", "Product", "Version"]))
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()