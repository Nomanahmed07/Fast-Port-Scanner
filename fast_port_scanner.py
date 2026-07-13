#!/usr/bin/env python3
import socket
import threading
import ipaddress
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Common Administrative and Security Ports
VIP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 554, 2869, 5357, 10243]

TOP_100_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 139, 143, 161, 
    179, 443, 445, 465, 514, 515, 554, 993, 995, 1025, 1080, 1433, 1434, 1723, 1900, 2000, 
    2049, 2869, 3000, 3306, 3389, 4444, 5000, 5060, 5357, 5432, 5900, 6000, 8000, 8080, 8443, 8888, 10243
]

PORTS_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
    110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 
    554: "RTSP", 1433: "MSSQL", 2869: "ICSLAP (SSDP)", 3306: "MySQL", 3389: "RDP", 
    5357: "WSDAPI", 8080: "HTTP-Proxy", 10243: "MS-WMIS"
}

print_lock = threading.Lock()
report_lines = []
json_findings = {}

def log_and_print(text):
    print(text)
    report_lines.append(text)

def parse_target_input(target_str):
    target_str = target_str.strip()
    if '/' in target_str:
        try:
            net = ipaddress.IPv4Network(target_str, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError: return []
    match = re.match(r'^([\d\.]+)\-(\d+)$', target_str)
    if match:
        base_ip = match.group(1)
        end_range = int(match.group(2))
        ip_parts = base_ip.split('.')
        if len(ip_parts) == 4 and 0 <= end_range <= 255:
            start_range = int(ip_parts[3])
            return [f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{i}" for i in range(start_range, end_range + 1)]
    try:
        ipaddress.IPv4Address(target_str)
        return [target_str]
    except ValueError: return []

def check_host_alive(ip):
    for port in [135, 445, 80, 22, 443]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        res = s.connect_ex((ip, port))
        s.close()
        if res == 0: return ip
    return None

def query_smb_version(target_ip):
    buffer = (
        b'\x00\x00\x00\x54' 
        b'\xff\x53\x4d\x42' 
        b'\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00'
        b'\x00\x31\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x4c'
        b'\x4d\x31\x2e\x32\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32'
        b'\x00\x02\x53\x4d\x42\x20\x32\x2e\x00\x02\x53\x4d\x42\x20\x32\x2e\x31\x00'
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target_ip, 445))
        s.send(buffer)
        data = s.recv(1024)
        s.close()
        
        if len(data) > 36 and data[4:8] == b'\xffSMB':
            extracted = re.findall(b'W\x00i\x00n\x00d\x00o\x00w\x00s\x00\x20\x00[A-Za-z0-9\.\x20\x00]+', data)
            if extracted:
                return extracted[0].replace(b'\x00', b'').decode('utf-8', errors='ignore')
            return "Windows (Legacy/Vulnerable Core Target Structure Detected)"
        elif len(data) > 4 and data[4:8] == b'\xfeSMB':
            return "Modern Windows Operating System / Enterprise Samba Node"
    except Exception:
        pass
    return "Unknown Operating System (Agnostic Node)"

def grab_generic_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, port))
        
        if port in [80, 5357, 10243]:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 21:
            pass 
        else:
            s.send(b"\r\n")
            
        banner = s.recv(512).decode('utf-8', errors='ignore').strip()
        s.close()
        if banner:
            return re.sub(r'[\r\n\t]+', ' | ', banner[:100])
    except Exception:
        pass
    return "No Response Data"

def scan_single_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    result = s.connect_ex((ip, port))
    s.close()
    if result == 0:
        banner = grab_generic_banner(ip, port)
        service = PORTS_SERVICES.get(port, "Dynamic/Unknown Service")
        return (port, service, banner)
    return None

def audit_host(ip, selected_ports):
    log_and_print(f"\n▶️ Commencing Audit for Active Host: {ip}")
    log_and_print("-" * 60)
    
    open_ports = []
    json_findings[ip] = {"status": "alive", "open_ports": []}
    
    max_workers = 150 if len(selected_ports) > 500 else 50
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_single_port, ip, port): port for port in selected_ports}
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
                
    open_ports.sort(key=lambda x: x[0])
    
    has_smb_or_rpc = False
    for port, svc, banner in open_ports:
        if port in [135, 139, 445]:
            has_smb_or_rpc = True
        log_and_print(f"  [+] Port {port} [{svc}]: OPEN")
        log_and_print(f"      └── BANNER: {banner}")
        
        json_findings[ip]["open_ports"].append({
            "port": port,
            "service": svc,
            "banner": banner
        })
        
    if has_smb_or_rpc:
        os_fingerprint = query_smb_version(ip)
        log_and_print(f"  [💻 OS DETECTION] Fingerprint Result: {os_fingerprint}")
    else:
        os_fingerprint = "Non-Windows Node or Missing Infrastructure Services"
        log_and_print(f"  [💻 OS DETECTION] Fingerprint Result: {os_fingerprint}")
        
    json_findings[ip]["os_fingerprint"] = os_fingerprint
    log_and_print("-" * 60)

def main():
    while True:
        print("\n" + "="*70)
        print("                        FAST PORT SCANNER                            ")
        print("="*70)
        print(" [1] Scan Custom VIP Security Ports (Quick Subnet/Host Audit)")
        print(" [2] Scan Top Threat Profiles (Top 50 Common Ports)")
        print(" [3] Full Network Range Scan (1 - 65535) [Optimized Threading]")
        print(" [4] Exit Application")
        print("-" * 70)
        
        try:
            choice = input("Select operation option [1-4]: ").strip()
            if choice == '4':
                print("[*] Exiting application safely. Goodbye!")
                break
            if choice not in ['1', '2', '3']:
                print("[-] Invalid execution choice.")
                continue
                
            target_input = input("Enter Target IP / Range / Subnet: ").strip()
            targets = parse_target_input(target_input)
            
            if not targets:
                print("[-] Scope Parsing Failed. Use formats: 192.168.1.1, 192.168.1.1-50, 192.168.1.0/24")
                continue
                
            if choice == '1': ports = VIP_PORTS
            elif choice == '2': ports = TOP_100_PORTS
            else: ports = list(range(1, 65536))
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_and_print("\n" + "="*70)
            log_and_print(f"[*] Audit Scope       : {target_input} ({len(targets)} Total Potential Hosts)")
            log_and_print(f"[*] Initiation Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            log_and_print("="*70)
            
            log_and_print("[*] Running discovery sweep across targets...")
            
            # Optimized Multi-Threaded Host Discovery
            live_hosts = []
            with ThreadPoolExecutor(max_workers=50) as executor:
                discovery_futures = [executor.submit(check_host_alive, ip) for ip in targets]
                for future in as_completed(discovery_futures):
                    result = future.result()
                    if result:
                        live_hosts.append(result)
            
            log_and_print(f"[*] Discovery Phase Done: Found {len(live_hosts)} Active Live Targets.")
            
            json_findings.clear()
            
            for host in live_hosts:
                audit_host(host, ports)
                
            log_and_print("\n[-] Network audit routine finalized cleanly.")
            
            # Export TXT Report
            txt_filename = f"network_report_{timestamp}.txt"
            with open(txt_filename, 'w') as f:
                f.write("\n".join(report_lines))
                
            # Export JSON Report
            json_filename = f"network_report_{timestamp}.json"
            meta_payload = {
                "scan_metadata": {
                    "scope": target_input,
                    "hosts_discovered": len(live_hosts),
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                },
                "results": json_findings
            }
            with open(json_filename, 'w') as jf:
                json.dump(meta_payload, jf, indent=4)
                
            print(f"======================================================================")
            print(f"[📊 REPORTS EXPORTED SUCCESSFULLY]")
            print(f"   [+] Plain-Text Log : {txt_filename}")
            print(f"   [+] Structured JSON: {json_filename}")
            print(f"======================================================================")
            report_lines.clear()
            
        except KeyboardInterrupt:
            print("\n[-] Operation aborted by user.")
            break

if __name__ == "__main__":
    main()
