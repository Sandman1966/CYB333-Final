import nmap


def scan_network():
    nm = nmap.PortScanner()

    # request for what network to scan
    target_network = input("Enter the network to scan (192.168.1.0/24): ")

    print(f"Scanning network {target_network}...")
    nm.scan(hosts=target_network, arguments='-sn')  # Perform host discovery

    # List discovered hosts
    print("\nHosts discovered:")
    for host in nm.all_hosts():
        print(f"Host: {host} \tState: {nm[host].state()}")

    # request to scan a specific port
    if input("\nDo you want to scan specific ports? (y/n): ").lower() == 'y':
        target_hosts = list(nm.all_hosts())
        ports_to_scan = input("Enter specific ports to scan (e.g., 80,443,22): ")

        # Convert ports to a list
        ports_list = [int(port.strip()) for port in ports_to_scan.split(',') if port.strip().isdigit()]

        # Scan specific ports
        for host in target_hosts:
            print(f"\nScanning ports on {host}...")
            nm.scan(hosts=host, ports=','.join(map(str, ports_list)), arguments='-sS')

            # Display results for specific ports
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    print(f"Port: {port}\tState: {state}")

    print("\nScan complete.")


if __name__ == "__main__":
    scan_network()
