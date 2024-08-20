import argparse
import socket
import sys
import threading
from queue import Queue

def scan_port(target, port, result_queue, options):
    try:
        
        sock_type = socket.SOCK_STREAM if options.use_tcp else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, sock_type) as sock:
            sock.settimeout(1.0) 
            
            
            if options.detect_version:
                if options.use_tcp:
                    sock.connect((target, port))
                    banner = sock.recv(1024).decode().strip() 
                else:
                    banner = ''
                result_queue.put((port, banner))  
            else:
                if sock.connect_ex((target, port)) == 0:  
                    result_queue.put(port)
    except:
        pass  

def scan_ports(target, ports, options):
    result_queue = Queue()
    threads = []    
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(target, port, result_queue, options))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    
    results = []
    while not result_queue.empty():
        results.append(result_queue.get())

    return results

def parse_port_input(port_input):
    ports = []
    try:
        for part in port_input.split(','):
            if '-' in part:  # Handle port range 
			start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:  
                ports.append(int(part))
    except ValueError:
        print(f"Error: Invalid port input '{port_input}'. Please specify correct ranges.")
        sys.exit(1)
    return ports

def main():
    parser = argparse.ArgumentParser(description="Multi-threaded Python Port Scanner")
    parser.add_argument("target", help="Target IP or domain name to scan")
    parser.add_argument("-p", "--ports", default="1-1024", 
                        help="Ports to scan. Use range (e.g., 1-1024) or comma-separated list (e.g., 22,80,443)")
    parser.add_argument("--tcp", action="store_true", help="Scan using TCP (default)")
    parser.add_argument("--version", action="store_true", help="Grab service version (banner grabbing)")

    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Error: Unable to resolve the target '{args.target}'.")
        sys.exit(1)

    ports = parse_port_input(args.ports)

    scan_options = argparse.Namespace(
        use_tcp=not args.udp,  
        detect_version=args.version
    )

    open_ports = scan_ports(target_ip, ports, scan_options)

    if open_ports:
        print(f"Open ports on {args.target}:")
        for result in open_ports:
            if isinstance(result, tuple):  
                print(f"Port {result[0]}: {result[1]}")
            else:
                print(f"Port {result} is open.")
    else:
        print(f"No open ports found on {args.target}.")

if __name__ == "__main__":
    main()
