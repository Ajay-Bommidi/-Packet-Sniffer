import os
import time
import scapy.all as scapy
import psutil
import pyfiglet
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn
from colorama import Fore, Style

# Console for CLI Outputs
console = Console()

# Create 'captures' directory if not exists
if not os.path.exists("captures"):
    os.mkdir("captures")

# Generate a new .pcap file for each session
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
pcap_file = f"captures/capture_{timestamp}.pcap"

# Display ASCII Art
def display_banner():
    ascii_banner = pyfiglet.figlet_format("Packet Sniffer")
    console.print(f"[bold cyan]{ascii_banner}[/bold cyan]")
    console.print("[bold yellow]🔥 Advanced Network Packet Analyzer 🔥[/bold yellow]\n")

# Detect available network interfaces
def list_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

# Get user-selected interface
def get_user_interface():
    interfaces = list_interfaces()
    console.print("\n🔍 [bold cyan]Available Network Interfaces:[/bold cyan]\n")
    for idx, iface in enumerate(interfaces):
        console.print(f"[{idx + 1}] [bold yellow]{iface}[/bold yellow]")
    
    while True:
        try:
            choice = int(console.input("\n👉 [bold green]Select an interface (number): [/bold green]"))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                console.print("[bold red]❌ Invalid selection! Try again.[/bold red]")
        except ValueError:
            console.print("[bold red]❌ Please enter a valid number.[/bold red]")

# Table for live packet display
table = Table(title="🌐 Live Network Packet Capture 🌐", show_lines=True)
table.add_column("Time", justify="center", style="cyan", no_wrap=True)
table.add_column("Source IP", style="yellow", no_wrap=True)
table.add_column("Destination IP", style="green", no_wrap=True)
table.add_column("Protocol", style="magenta", no_wrap=True)
table.add_column("Size", justify="right", style="red", no_wrap=True)

# Packet Statistics
packet_count = 0
total_data = 0
packet_data = []

# Progress bar for traffic volume
progress = Progress(
    TextColumn("[bold blue]Captured Packets:[/] {task.completed}"),
    BarColumn(bar_width=None),
    TextColumn("[bold green]{task.percentage:.0f}%[/]"),
    console=console
)
task = progress.add_task("Packet Capture Progress", total=5000)

# Get correct protocol name
def get_protocol_name(proto):
    """Returns the protocol name from protocol number."""
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocol_map.get(proto, f"Other ({proto})")

# Process each packet
def process_packet(packet):
    global packet_count, total_data

    time_now = datetime.now().strftime("%H:%M:%S")
    src_ip = dst_ip = protocol = "Unknown"
    length = len(packet)

    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = get_protocol_name(packet[scapy.IP].proto)

    # Increment counters
    packet_count += 1
    total_data += length

    # Update Progress Bar
    progress.update(task, advance=1)

    # Append to table
    packet_data.append([time_now, src_ip, dst_ip, protocol, str(length)])

    # Display packet in CLI
    console.print(f"{Fore.CYAN}{time_now}{Style.RESET_ALL} | "
                  f"{Fore.YELLOW}{src_ip}{Style.RESET_ALL} -> "
                  f"{Fore.GREEN}{dst_ip}{Style.RESET_ALL} | "
                  f"{Fore.MAGENTA}{protocol}{Style.RESET_ALL} | "
                  f"{Fore.RED}{length} bytes{Style.RESET_ALL}")

    # Save to .pcap file
    scapy.wrpcap(pcap_file, packet, append=True)

# Start packet capture
def start_sniffing(interface):
    console.print(f"\n🚀 [bold green]Starting Packet Capture on {interface}...[/bold green]\n")
    with Live(table, refresh_per_second=2), progress:
        scapy.sniff(prn=process_packet, store=False, iface=interface)

if __name__ == "__main__":
    display_banner()
    user_interface = get_user_interface()
    console.print(f"📂 [bold green]Saving packets to:[/bold green] {pcap_file}\n")

    try:
        start_sniffing(user_interface)
    except KeyboardInterrupt:
        console.print("\n🔴 [bold red]Capture stopped![/bold red] Open the .pcap file in Wireshark.\n")
        console.print(f"📊 [bold cyan]Total Packets Captured:[/bold cyan] {packet_count}")
        console.print(f"📦 [bold cyan]Total Data Transferred:[/bold cyan] {total_data} bytes\n")
