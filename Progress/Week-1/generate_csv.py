#!/usr/bin/env python3

"""
=============================================================
  Nmap XML Results → Consolidated CSV Asset Report Generator
=============================================================
Parses Nmap XML output files and merges them into a single
CSV report containing: IP, Hostname, OS Guess, OS Accuracy,
Port, State, Protocol, Service, Version, Product, Extra Info,
and Vulnerabilities.

Expected inputs (as produced by recon.sh):
  - results/aggressive_scan.xml
  - results/vuln_scan.xml
  - results/live_hosts.txt  (for hosts with no open ports)
=============================================================
"""

import xml.etree.ElementTree as ET
import csv
import os
import sys

RESULTS_DIR = "results"

# XML files to parse (in priority order for data merging)
XML_FILES = {
    "aggressive_scan": os.path.join(RESULTS_DIR, "aggressive_scan.xml"),
    "vuln_scan": os.path.join(RESULTS_DIR, "vuln_scan.xml"),
}

OUTPUT_CSV = os.path.join(RESULTS_DIR, "final_asset_report.csv")


def parse_nmap_xml(xml_file):
    """Parse a single Nmap XML file and return structured host data."""
    hosts_data = {}

    if not os.path.exists(xml_file):
        print(f"  [!] File not found: {xml_file} — Skipping.")
        return hosts_data

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"  [!] XML parse error in {xml_file}: {e}")
        return hosts_data

    for host in root.findall("host"):
        # --- Status ---
        status_elem = host.find("status")
        if status_elem is not None and status_elem.get("state") != "up":
            continue

        # --- IP Address ---
        ip_address = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip_address = addr.get("addr", "")
                break
        if not ip_address:
            continue

        # --- Hostname ---
        hostname = ""
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        # --- OS Detection ---
        os_name = ""
        os_accuracy = ""
        os_elem = host.find("os")
        if os_elem is not None:
            os_matches = os_elem.findall("osmatch")
            if os_matches:
                best_match = os_matches[0]
                os_name = best_match.get("name", "")
                os_accuracy = best_match.get("accuracy", "")

        # --- Ports & Services ---
        ports_data = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_id = port.get("portid", "")
                protocol = port.get("protocol", "")

                state_elem = port.find("state")
                state = state_elem.get("state", "") if state_elem is not None else ""

                service_elem = port.find("service")
                service_name = ""
                product = ""
                version = ""
                extra_info = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    extra_info = service_elem.get("extrainfo", "")

                # --- Vulnerability Scripts (per-port) ---
                vulns = []
                for script in port.findall("script"):
                    script_id = script.get("id", "")
                    script_output = script.get("output", "").strip()

                    # Check if it's a vuln-related script
                    if any(keyword in script_id.lower() for keyword in
                           ["vuln", "cve", "exploit", "smb-vuln",
                            "ssl", "http-vuln", "ftp-vuln"]):
                        # Extract CVE IDs if present
                        cve_ids = []
                        for table in script.findall(".//table"):
                            for elem in table.findall(".//elem"):
                                if elem.text and "CVE-" in elem.text:
                                    cve_ids.append(elem.text.strip())

                        vuln_entry = script_id
                        if cve_ids:
                            vuln_entry += f" ({', '.join(cve_ids)})"
                        vulns.append(vuln_entry)

                    # Also check output for VULNERABLE keyword
                    if "VULNERABLE" in script_output.upper() and script_id not in [v.split(" ")[0] for v in vulns]:
                        vulns.append(script_id)

                ports_data.append({
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extra_info": extra_info,
                    "vulnerabilities": "; ".join(vulns) if vulns else "",
                })

        # --- Host-level Scripts (hostscript) — merge into all ports ---
        host_vulns = []
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                script_id = script.get("id", "")
                script_output = script.get("output", "").strip()
                if any(keyword in script_id.lower() for keyword in
                       ["vuln", "cve", "exploit", "smb-vuln"]):
                    # Extract CVE IDs if present
                    cve_ids = []
                    for table in script.findall(".//table"):
                        for elem in table.findall(".//elem"):
                            if elem.text and "CVE-" in elem.text:
                                cve_ids.append(elem.text.strip())
                    vuln_entry = script_id
                    if cve_ids:
                        vuln_entry += f" ({', '.join(cve_ids)})"
                    host_vulns.append(vuln_entry)
                elif "VULNERABLE" in script_output.upper():
                    host_vulns.append(script_id)

        # --- Store Data ---
        if ip_address not in hosts_data:
            hosts_data[ip_address] = {
                "ip": ip_address,
                "hostname": hostname,
                "os_name": os_name,
                "os_accuracy": os_accuracy,
                "host_vulns": host_vulns,
                "ports": {},
            }
        else:
            # Merge — fill in blanks
            existing = hosts_data[ip_address]
            if not existing["hostname"] and hostname:
                existing["hostname"] = hostname
            if not existing["os_name"] and os_name:
                existing["os_name"] = os_name
                existing["os_accuracy"] = os_accuracy
            if host_vulns:
                existing["host_vulns"].extend(host_vulns)

        # Merge port data
        for p in ports_data:
            port_key = f"{p['protocol']}/{p['port']}"
            if port_key not in hosts_data[ip_address]["ports"]:
                hosts_data[ip_address]["ports"][port_key] = p
            else:
                # Merge — fill in blanks for existing port
                existing_port = hosts_data[ip_address]["ports"][port_key]
                if not existing_port["product"] and p["product"]:
                    existing_port["product"] = p["product"]
                if not existing_port["version"] and p["version"]:
                    existing_port["version"] = p["version"]
                if not existing_port["extra_info"] and p["extra_info"]:
                    existing_port["extra_info"] = p["extra_info"]
                if p["vulnerabilities"]:
                    if existing_port["vulnerabilities"]:
                        existing_port["vulnerabilities"] += "; " + p["vulnerabilities"]
                    else:
                        existing_port["vulnerabilities"] = p["vulnerabilities"]

    return hosts_data


def merge_hosts(all_hosts, new_hosts):
    """Merge new host data into the main dictionary."""
    for ip, data in new_hosts.items():
        if ip not in all_hosts:
            all_hosts[ip] = data
        else:
            existing = all_hosts[ip]
            # Fill in blanks
            if not existing["hostname"] and data["hostname"]:
                existing["hostname"] = data["hostname"]
            if not existing["os_name"] and data["os_name"]:
                existing["os_name"] = data["os_name"]
                existing["os_accuracy"] = data["os_accuracy"]
            if data["host_vulns"]:
                existing["host_vulns"].extend(data["host_vulns"])

            # Merge ports
            for port_key, port_data in data["ports"].items():
                if port_key not in existing["ports"]:
                    existing["ports"][port_key] = port_data
                else:
                    ep = existing["ports"][port_key]
                    if not ep["product"] and port_data["product"]:
                        ep["product"] = port_data["product"]
                    if not ep["version"] and port_data["version"]:
                        ep["version"] = port_data["version"]
                    if not ep["extra_info"] and port_data["extra_info"]:
                        ep["extra_info"] = port_data["extra_info"]
                    if port_data["vulnerabilities"]:
                        if ep["vulnerabilities"]:
                            ep["vulnerabilities"] += "; " + port_data["vulnerabilities"]
                        else:
                            ep["vulnerabilities"] = port_data["vulnerabilities"]


def generate_csv(all_hosts, output_file):
    """Generate the final CSV report with the requested columns."""
    csv_headers = [
        "IP Address",
        "Hostname",
        "OS Guess",
        "OS Accuracy",
        "Port",
        "State",
        "Protocol",
        "Service",
        "Version",
        "Product",
        "Extra Info",
        "Vulnerabilities",
    ]

    rows = []

    def ip_sort_key(ip):
        try:
            return list(map(int, ip.split(".")))
        except ValueError:
            return [999, 999, 999, 999]

    for ip in sorted(all_hosts.keys(), key=ip_sort_key):
        host = all_hosts[ip]

        # Deduplicate host-level vulns
        host_vuln_str = "; ".join(sorted(set(host["host_vulns"]))) if host["host_vulns"] else ""

        # Format OS Accuracy with % sign
        os_accuracy_display = f"{host['os_accuracy']}%" if host["os_accuracy"] else "—"

        if host["ports"]:
            def port_sort_key(pk):
                try:
                    return int(pk.split("/")[1])
                except (IndexError, ValueError):
                    return 65535

            for port_key in sorted(host["ports"].keys(), key=port_sort_key):
                port_data = host["ports"][port_key]

                # Combine port-level and host-level vulnerabilities
                combined_vulns = port_data["vulnerabilities"]
                if host_vuln_str:
                    if combined_vulns:
                        combined_vulns += "; " + host_vuln_str
                    else:
                        combined_vulns = host_vuln_str

                # Deduplicate the combined vulns
                if combined_vulns:
                    vuln_parts = [v.strip() for v in combined_vulns.split(";") if v.strip()]
                    combined_vulns = "; ".join(dict.fromkeys(vuln_parts))  # preserve order, remove dupes

                rows.append([
                    host["ip"],
                    host["hostname"] if host["hostname"] else "—",
                    host["os_name"] if host["os_name"] else "—",
                    os_accuracy_display,
                    port_data["port"],
                    port_data["state"],
                    port_data["protocol"],
                    port_data["service"] if port_data["service"] else "—",
                    port_data["version"] if port_data["version"] else "—",
                    port_data["product"] if port_data["product"] else "—",
                    port_data["extra_info"] if port_data["extra_info"] else "—",
                    combined_vulns if combined_vulns else "—",
                ])
        else:
            # Host with no open ports — single row
            rows.append([
                host["ip"],
                host["hostname"] if host["hostname"] else "—",
                host["os_name"] if host["os_name"] else "—",
                os_accuracy_display,
                "—",
                "—",
                "—",
                "—",
                "—",
                "—",
                "—",
                host_vuln_str if host_vuln_str else "—",
            ])

    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(csv_headers)
        writer.writerows(rows)

    return len(rows)


def main():
    print("=" * 60)
    print("  Nmap XML → CSV Asset Report Generator")
    print("=" * 60)

    all_hosts = {}
    any_xml_found = False

    for scan_name, xml_path in XML_FILES.items():
        print(f"\n[*] Parsing: {scan_name} → {xml_path}")
        hosts = parse_nmap_xml(xml_path)
        if hosts:
            any_xml_found = True
        print(f"    Found {len(hosts)} host(s)")
        merge_hosts(all_hosts, hosts)

    if not any_xml_found:
        print("\n[!] No XML scan files found (aggressive_scan.xml / vuln_scan.xml).")
        print("    Make sure you ran recon.sh and that the results are in 'results/'.")
        sys.exit(1)

    print(f"\n{'=' * 60}")
    print(f"[*] Total unique hosts with scan data: {len(all_hosts)}")

    # Also add any hosts from live_hosts.txt that might not have port data
    live_hosts_file = os.path.join(RESULTS_DIR, "live_hosts.txt")
    if os.path.exists(live_hosts_file):
        with open(live_hosts_file, "r") as f:
            for line in f:
                ip = line.strip()
                if ip and ip not in all_hosts:
                    all_hosts[ip] = {
                        "ip": ip,
                        "hostname": "",
                        "os_name": "",
                        "os_accuracy": "",
                        "host_vulns": [],
                        "ports": {},
                    }

    if not all_hosts:
        print("[!] No data found. Make sure XML files exist in results/ and live_hosts.txt is populated.")
        sys.exit(1)

    row_count = generate_csv(all_hosts, OUTPUT_CSV)

    print(f"\n[✓] CSV report generated successfully!")
    print(f"[✓] File: {OUTPUT_CSV}")
    print(f"[✓] Total rows: {row_count}")
    print(f"[✓] Total assets: {len(all_hosts)}")

    # Print summary table
    print(f"\n{'=' * 60}")
    print("  ASSET SUMMARY")
    print(f"{'=' * 60}")
    print(f"{'IP Address':<18} {'Hostname':<20} {'OS Guess':<25} {'Open Ports':<10}")
    print(f"{'-'*18} {'-'*20} {'-'*25} {'-'*10}")

    def ip_sort_key(ip):
        try:
            return list(map(int, ip.split(".")))
        except ValueError:
            return [999, 999, 999, 999]

    for ip in sorted(all_hosts.keys(), key=ip_sort_key):
        h = all_hosts[ip]
        open_ports = sum(1 for p in h["ports"].values() if p["state"] == "open")
        os_short = (h["os_name"][:22] + "...") if len(h["os_name"]) > 25 else (h["os_name"] if h["os_name"] else "—")
        hn_short = (h["hostname"][:17] + "...") if len(h["hostname"]) > 20 else (h["hostname"] if h["hostname"] else "—")
        print(f"{ip:<18} {hn_short:<20} {os_short:<25} {open_ports:<10}")

    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
