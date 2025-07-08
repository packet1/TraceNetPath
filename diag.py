import socket
import subprocess
import psutil
import dns.resolver
import ipaddress
from datetime import datetime

LOGFILE = "network_diagnostic_output.txt"

def log(msg):
    print(msg)
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def resolve_fqdn(fqdn):
    try:
        ip = socket.gethostbyname(fqdn)
        return ip
    except socket.gaierror:
        return None

def show_all_dns_records(fqdn):
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV']
    log(f"\n🌐 DNS Records for: {fqdn}")
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(fqdn, rtype, lifetime=3)
            for rdata in answers:
                log(f"  {rtype}: {rdata.to_text()}")
        except dns.resolver.NoAnswer:
            log(f"  {rtype}: [No Answer]")
        except dns.resolver.NXDOMAIN:
            log(f"  {rtype}: [Domain does not exist]")
            break
        except dns.resolver.NoNameservers:
            log(f"  {rtype}: [No nameservers responded]")
        except Exception as e:
            log(f"  {rtype}: [Error: {str(e)}]")

def reverse_dns_lookup(ip):
    try:
        ptr = socket.gethostbyaddr(ip)[0]
        log(f"\n🔁 PTR (Reverse DNS) Lookup for {ip}: {ptr}")
    except Exception as e:
        log(f"\n🔁 PTR (Reverse DNS) Lookup for {ip}: [Failed — {e}]")

def show_dns_alias_chain_and_ptr(fqdn):
    log(f"\n🔗 Alias (CNAME) Chain Diagram:")
    resolver = dns.resolver.Resolver()
    chain = [fqdn]
    current = fqdn

    try:
        while True:
            answer = resolver.resolve(current, 'CNAME', lifetime=3)
            cname = str(answer[0]).strip('.')
            chain.append(cname)
            current = cname
    except dns.resolver.NoAnswer:
        pass
    except Exception as e:
        log(f"  [Error resolving alias chain: {str(e)}]")
        return

    for i in range(len(chain)):
        indent = "  " * i
        arrow = "↓" if i < len(chain) - 1 else "→"
        log(f"{indent}{chain[i]} {arrow}")

    try:
        ip_answer = dns.resolver.resolve(chain[-1], 'A')
        ip = str(ip_answer[0])
        log(f"{'  ' * len(chain)}Final A Record → {ip}")
        reverse_dns_lookup(ip)
    except Exception:
        log(f"{'  ' * len(chain)}[Could not resolve final IP]")

def test_tcp_connection(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(3)
        try:
            sock.connect((ip, port))
            return True
        except:
            return False

def run_tracert(ip):
    log("\n🛰️ Tracing route (real-time output)...")
    process = subprocess.Popen(
        ['tracert', ip],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    for line in process.stdout:
        line = line.strip()
        print(line)
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    process.wait()

def get_network_adapter_used(remote_ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((remote_ip, 80))
            local_ip = s.getsockname()[0]
    except Exception:
        return "Could not determine local interface"

    adapters = psutil.net_if_addrs()
    for adapter_name, addrs in adapters.items():
        for addr in addrs:
            if addr.address == local_ip:
                return f"{adapter_name} ({local_ip})"

    return f"Local IP {local_ip} used, but adapter name not found"

def is_cgnat(ip):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return False

def main():
    with open(LOGFILE, "w", encoding="utf-8") as f:
        f.write(f"Network Diagnostic Log - {datetime.now()}\n\n")

    fqdn = input("Enter application FQDN: ").strip()
    port_input = input("Enter TCP port: ").strip()

    try:
        port = int(port_input)
    except ValueError:
        log("❌ Invalid port.")
        return

    ip = resolve_fqdn(fqdn)
    if not ip:
        log("❌ Could not resolve hostname.")
        return

    log(f"\n✅ Resolved {fqdn} to {ip}")

    show_all_dns_records(fqdn)
    show_dns_alias_chain_and_ptr(fqdn)

    adapter = get_network_adapter_used(ip)
    log(f"\n🔌 Network adapter used: {adapter}")

    local_ip = adapter.split("(")[-1].rstrip(")") if "(" in adapter else None

    if is_cgnat(ip) and local_ip and is_cgnat(local_ip):
        log("\n🌐 This application route is through the ZTNA agent")
        log("⏩ Skipping traceroute.")
    else:
        run_tracert(ip)

    if test_tcp_connection(ip, port):
        log(f"\n📡 Successfully connected to {ip}:{port}")
    else:
        log(f"\n❌ Could not connect to {ip}:{port}")

    log(f"\n📁 Results saved to: {LOGFILE}")

if __name__ == "__main__":
    main()
