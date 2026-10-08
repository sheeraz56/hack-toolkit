#!/usr/bin/env python3

import csv
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import urllib.request
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog


APP_NAME = "HACK-TOOLKIT 1.0"

DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,"
    "445,587,993,995,1433,1521,3306,3389,5432,5900,"
    "6379,8080,8443,8888"
)


def command_exists(command):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        path = os.path.join(directory, command)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return True
    return False


def run_command(command, timeout=20):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "Command timed out."
    except Exception as exc:
        return f"Error: {exc}"


def valid_target(value):
    value = value.strip()

    if not value:
        return False

    if len(value) > 253:
        return False

    return bool(re.fullmatch(r"[A-Za-z0-9_.:-]+", value))


class HackToolkit(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title(APP_NAME)
        self.geometry("1150x760")
        self.minsize(950, 600)

        self.configure(bg="#0b1017")

        self.results = []
        self.stop_requested = False

        self.setup_style()
        self.build_gui()

        self.log("=" * 70)
        self.log(APP_NAME)
        self.log("Authorized security reconnaissance toolkit")
        self.log("=" * 70)
        self.log("Enter an IP address, hostname, or domain above.")
        self.log("Only scan systems you own or are authorized to test.")
        self.log("")

    # ---------------------------------------------------------
    # STYLE
    # ---------------------------------------------------------

    def setup_style(self):

        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "TFrame",
            background="#0b1017"
        )

        style.configure(
            "TLabel",
            background="#0b1017",
            foreground="#e5edf5"
        )

        style.configure(
            "Title.TLabel",
            background="#0b1017",
            foreground="#55eaff",
            font=("DejaVu Sans", 20, "bold")
        )

        style.configure(
            "TButton",
            padding=8,
            font=("DejaVu Sans", 9, "bold")
        )

        style.configure(
            "TLabelframe",
            background="#0b1017",
            foreground="#55eaff"
        )

        style.configure(
            "TLabelframe.Label",
            background="#0b1017",
            foreground="#55eaff"
        )

        style.configure(
            "TCheckbutton",
            background="#0b1017",
            foreground="#e5edf5"
        )

    # ---------------------------------------------------------
    # GUI
    # ---------------------------------------------------------

    def build_gui(self):

        # Header
        header = ttk.Frame(self, padding=15)
        header.pack(fill="x")

        ttk.Label(
            header,
            text="⚡ HACK-TOOLKIT",
            style="Title.TLabel"
        ).pack(side="left")

        ttk.Label(
            header,
            text="  v1.0 • Network Reconnaissance"
        ).pack(side="left")

        # Target section
        target_frame = ttk.LabelFrame(
            self,
            text=" Target "
        )
        target_frame.pack(
            fill="x",
            padx=15,
            pady=5
        )

        ttk.Label(
            target_frame,
            text="IP / Host / Domain:"
        ).grid(
            row=0,
            column=0,
            padx=8,
            pady=10
        )

        self.target_entry = ttk.Entry(
            target_frame,
            width=40
        )

        self.target_entry.grid(
            row=0,
            column=1,
            padx=5,
            pady=10
        )

        self.target_entry.insert(
            0,
            "192.168.1.1"
        )

        ttk.Label(
            target_frame,
            text="Ports:"
        ).grid(
            row=0,
            column=2,
            padx=(20, 5)
        )

        self.port_entry = ttk.Entry(
            target_frame,
            width=48
        )

        self.port_entry.grid(
            row=0,
            column=3,
            padx=5
        )

        self.port_entry.insert(
            0,
            DEFAULT_PORTS
        )

        # Options
        options = ttk.Frame(self)
        options.pack(
            fill="x",
            padx=15,
            pady=5
        )

        ttk.Label(
            options,
            text="Timeout:"
        ).pack(side="left")

        self.timeout_entry = ttk.Entry(
            options,
            width=7
        )

        self.timeout_entry.pack(
            side="left",
            padx=5
        )

        self.timeout_entry.insert(
            0,
            "1.0"
        )

        self.banner_var = tk.BooleanVar(
            value=True
        )

        ttk.Checkbutton(
            options,
            text="Service / Banner probe",
            variable=self.banner_var
        ).pack(
            side="left",
            padx=15
        )

        self.stop_button = ttk.Button(
            options,
            text="STOP",
            command=self.stop_scan
        )

        self.stop_button.pack(
            side="right"
        )

        # Scanner buttons
        scan_frame = ttk.LabelFrame(
            self,
            text=" Reconnaissance "
        )

        scan_frame.pack(
            fill="x",
            padx=15,
            pady=5
        )

        buttons = [
            ("PING", self.ping_scan),
            ("DNS", self.dns_scan),
            ("TCP PORTS", self.port_scan),
            ("HTTP", self.http_scan),
            ("TLS", self.tls_scan),
            ("TRACEROUTE", self.trace_scan),
            ("WHOIS", self.whois_scan),
            ("LOCAL LAN", self.local_scan),
            ("FULL SCAN", self.full_scan),
        ]

        for index, (name, function) in enumerate(buttons):

            ttk.Button(
                scan_frame,
                text=name,
                command=function
            ).grid(
                row=0,
                column=index,
                padx=4,
                pady=8
            )

        # Report buttons
        report_frame = ttk.Frame(self)
        report_frame.pack(
            fill="x",
            padx=15,
            pady=5
        )

        ttk.Button(
            report_frame,
            text="SAVE TXT",
            command=lambda: self.save_report("txt")
        ).pack(
            side="left",
            padx=4
        )

        ttk.Button(
            report_frame,
            text="SAVE JSON",
            command=lambda: self.save_report("json")
        ).pack(
            side="left",
            padx=4
        )

        ttk.Button(
            report_frame,
            text="SAVE CSV",
            command=lambda: self.save_report("csv")
        ).pack(
            side="left",
            padx=4
        )

        ttk.Button(
            report_frame,
            text="CLEAR",
            command=self.clear_output
        ).pack(
            side="left",
            padx=4
        )

        # Output
        output_frame = ttk.Frame(
            self,
            padding=15
        )

        output_frame.pack(
            fill="both",
            expand=True
        )

        self.output = tk.Text(
            output_frame,
            background="#070b10",
            foreground="#bdf7ff",
            insertbackground="#ffffff",
            font=("DejaVu Sans Mono", 10),
            wrap="none"
        )

        vertical = ttk.Scrollbar(
            output_frame,
            orient="vertical",
            command=self.output.yview
        )

        horizontal = ttk.Scrollbar(
            output_frame,
            orient="horizontal",
            command=self.output.xview
        )

        self.output.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set
        )

        self.output.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        vertical.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        horizontal.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        output_frame.rowconfigure(
            0,
            weight=1
        )

        output_frame.columnconfigure(
            0,
            weight=1
        )

    # ---------------------------------------------------------
    # GENERAL
    # ---------------------------------------------------------

    def log(self, message):

        def update():

            self.output.insert(
                "end",
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"{message}\n"
            )

            self.output.see("end")

        self.after(
            0,
            update
        )

    def get_target(self):

        target = self.target_entry.get().strip()

        if not valid_target(target):

            messagebox.showerror(
                "Invalid Target",
                "Enter a valid IP address, hostname, or domain."
            )

            return None

        return target

    def get_timeout(self):

        try:

            value = float(
                self.timeout_entry.get()
            )

            if value <= 0:
                raise ValueError

            return min(value, 10)

        except Exception:

            return 1.0

    def record(self, module, data):

        self.results.append(
            {
                "time": datetime.now().isoformat(
                    timespec="seconds"
                ),
                "target": self.target_entry.get().strip(),
                "module": module,
                "data": data
            }
        )

    def threaded(self, function):

        self.stop_requested = False

        thread = threading.Thread(
            target=function,
            daemon=True
        )

        thread.start()

    def stop_scan(self):

        self.stop_requested = True

        self.log(
            "STOP requested..."
        )

    # ---------------------------------------------------------
    # PING
    # ---------------------------------------------------------

    def ping_scan(self):

        target = self.get_target()

        if not target:
            return

        def worker():

            self.log(
                f"PING: {target}"
            )

            command = [
                "ping",
                "-c",
                "4",
                "-W",
                "2",
                target
            ]

            result = run_command(
                command,
                15
            )

            self.log(result)

            self.record(
                "ping",
                result
            )

        self.threaded(worker)

    # ---------------------------------------------------------
    # DNS
    # ---------------------------------------------------------

    def dns_scan(self):

        target = self.get_target()

        if not target:
            return

        def worker():

            self.log(
                f"DNS LOOKUP: {target}"
            )

            try:

                information = socket.getaddrinfo(
                    target,
                    None
                )

                addresses = sorted(
                    {
                        item[4][0]
                        for item in information
                    }
                )

                result = "\n".join(
                    addresses
                )

            except Exception as exc:

                result = str(exc)

            self.log(result)

            self.record(
                "dns",
                result
            )

        self.threaded(worker)

    # ---------------------------------------------------------
    # PORT PARSER
    # ---------------------------------------------------------

    def parse_ports(self):

        raw = self.port_entry.get().strip()

        ports = set()

        for item in raw.split(","):

            item = item.strip()

            if not item:
                continue

            if "-" in item:

                try:

                    first, last = item.split(
                        "-",
                        1
                    )

                    first = int(first)
                    last = int(last)

                    if first > last:
                        first, last = last, first

                    last = min(
                        last,
                        65535
                    )

                    for port in range(
                        first,
                        last + 1
                    ):
                        if 1 <= port <= 65535:
                            ports.add(port)

                except ValueError:
                    continue

            else:

                try:

                    port = int(item)

                    if 1 <= port <= 65535:
                        ports.add(port)

                except ValueError:
                    continue

        # Safety / GUI limit
        return sorted(ports)[:1000]

    # ---------------------------------------------------------
    # TCP PORT SCAN
    # ---------------------------------------------------------

    def port_scan(self):

        target = self.get_target()

        if not target:
            return

        ports = self.parse_ports()

        if not ports:

            messagebox.showerror(
                "Ports",
                "Enter ports like 22,80,443 or 1-100."
            )

            return

        def worker():

            self.log(
                f"TCP SCAN: {target}"
            )

            try:

                ip = socket.gethostbyname(
                    target
                )

            except Exception as exc:

                self.log(
                    f"DNS error: {exc}"
                )

                return

            self.log(
                f"Resolved target: {ip}"
            )

            timeout = self.get_timeout()

            open_ports = []

            for port in ports:

                if self.stop_requested:
                    break

                sock = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                )

                sock.settimeout(
                    timeout
                )

                try:

                    status = sock.connect_ex(
                        (ip, port)
                    )

                    if status == 0:

                        try:
                            service = socket.getservbyport(
                                port,
                                "tcp"
                            )
                        except Exception:
                            service = "unknown"

                        banner = ""

                        if self.banner_var.get():

                            try:

                                sock.settimeout(
                                    min(
                                        timeout,
                                        2
                                    )
                                )

                                sock.sendall(
                                    b"\r\n"
                                )

                                banner = sock.recv(
                                    256
                                ).decode(
                                    errors="replace"
                                ).strip()

                            except Exception:
                                pass

                        item = {
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": service,
                            "banner": banner
                        }

                        open_ports.append(
                            item
                        )

                        self.log(
                            f"OPEN  {port}/tcp  "
                            f"{service}  {banner}"
                        )

                finally:

                    sock.close()

            self.record(
                "tcp_scan",
                open_ports
            )

            self.log(
                f"TCP scan complete. "
                f"Open ports: {len(open_ports)}"
            )

        self.threaded(worker)

    # ---------------------------------------------------------
    # HTTP
    # ---------------------------------------------------------

    def http_scan(self):

        target = self.get_target()

        if not target:
            return

        def worker():

            self.log(
                f"HTTP/HTTPS HEADERS: {target}"
            )

            results = {}

            for scheme in (
                "http",
                "https"
            ):

                url = (
                    f"{scheme}://{target}/"
                )

                try:

                    request = urllib.request.Request(
                        url,
                        headers={
                            "User-Agent":
                            "HACK-TOOLKIT/1.0"
                        }
                    )

                    with urllib.request.urlopen(
                        request,
                        timeout=5
                    ) as response:

                        headers = dict(
                            response.headers
                        )

                        results[url] = {
                            "status":
                                response.status,
                            "headers":
                                headers
                        }

                        self.log(
                            f"{url} -> "
                            f"HTTP {response.status}"
                        )

                        for key, value in headers.items():

                            self.log(
                                f"  {key}: {value}"
                            )

                except Exception as exc:

                    results[url] = {
                        "error": str(exc)
                    }

            self.record(
                "http_headers",
                results
            )

        self.threaded(worker)

    # ---------------------------------------------------------
    # TLS
    # ---------------------------------------------------------

    def tls_scan(self):

        target = self.get_target()

        if not target:
            return

        def worker():

            self.log(
                f"TLS INFORMATION: {target}:443"
            )

            try:

                context = (
                    ssl.create_default_context()
                )

                with socket.create_connection(
                    (target, 443),
                    timeout=5
                ) as raw:

                    with context.wrap_socket(
                        raw,
                        server_hostname=target
                    ) as sock:

                        certificate = (
                            sock.getpeercert()
                        )

                        information = {
                            "tls_version":
                                sock.version(),
                            "cipher":
                                sock.cipher(),
                            "certificate":
                                certificate
                        }

                        self.log(
                            json.dumps(
                                information,
                                indent=2,
                                default=str
                            )
                        )

                        self.record(
                            "tls",
                            information
                        )

            except Exception as exc:

                self.log(
                    f"TLS error: {exc}"
                )

        self.threaded(worker)

    # ---------------------------------------------------------
    # TRACEROUTE
    # ---------------------------------------------------------

    def trace_scan(self):

        target = self.get_target()

        if not target:
            return

        def worker():

            self.log(
                f"TRACEROUTE: {target}"
            )

            if command_exists(
                "traceroute"
            ):

                command = [
                    "traceroute",
                    "-m",
                    "12",
                    "-w",
                    "1",
                    target
                ]

            elif command_exists(
                "tracepath"
            ):

                command = [
                    "tracepath",
                    "-m",
                    "12",
                    target
                ]

            else:

                result = (
                    "traceroute/tracepath "
                    "is not installed."
                )

                self.log(result)
                return

            result = run_command(
                command,
                30
            )

            self.log(result)

            self.record(
                "traceroute",
                result
            )

        self.threaded(worker)

    # ---------------------------------------------------------
    # WHOIS
    # ---------------------------------------------------------

    def whois_scan(self):

        target = self.get_target()

        if not target:
            return

        def worker():

            self.log(
                f"WHOIS: {target}"
            )

            if not command_exists(
                "whois"
            ):

                result = (
                    "whois is not installed.\n"
                    "Install with:\n"
                    "sudo apt install whois"
                )

            else:

                result = run_command(
                    ["whois", target],
                    25
                )

            self.log(result)

            self.record(
                "whois",
                result
            )

        self.threaded(worker)

    # ---------------------------------------------------------
    # LOCAL NETWORK DISCOVERY
    # ---------------------------------------------------------

    def local_scan(self):

        def worker():

            self.log(
                "LOCAL LAN DISCOVERY"
            )

            try:

                local_ip = socket.gethostbyname(
                    socket.gethostname()
                )

                if not local_ip.startswith(
                    (
                        "10.",
                        "192.168.",
                        "172."
                    )
                ):

                    self.log(
                        "Could not determine "
                        "a private LAN address."
                    )

                    return

                prefix = ".".join(
                    local_ip.split(".")[:3]
                )

                self.log(
                    f"Detected LAN: {prefix}.0/24"
                )

                alive = []

                for number in range(
                    1,
                    255
                ):

                    if self.stop_requested:
                        break

                    host = (
                        f"{prefix}.{number}"
                    )

                    result = subprocess.run(
                        [
                            "ping",
                            "-c",
                            "1",
                            "-W",
                            "1",
                            host
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )

                    if result.returncode == 0:

                        alive.append(
                            host
                        )

                        self.log(
                            f"ALIVE: {host}"
                        )

                self.record(
                    "local_discovery",
                    alive
                )

                self.log(
                    f"Discovery finished. "
                    f"{len(alive)} responsive hosts."
                )

            except Exception as exc:

                self.log(
                    f"LAN error: {exc}"
                )

        self.threaded(worker)

    # ---------------------------------------------------------
    # FULL SCAN
    # ---------------------------------------------------------

    def full_scan(self):

        target = self.get_target()

        if not target:
            return

        self.log(
            "Starting FULL SAFE RECONNAISSANCE..."
        )

        self.ping_scan()
        self.dns_scan()
        self.port_scan()
        self.http_scan()
        self.tls_scan()

    # ---------------------------------------------------------
    # SAVE REPORT
    # ---------------------------------------------------------

    def save_report(self, report_type):

        if not self.results:

            messagebox.showinfo(
                "No Results",
                "Run a scan first."
            )

            return

        extension = {
            "txt": ".txt",
            "json": ".json",
            "csv": ".csv"
        }[report_type]

        path = filedialog.asksaveasfilename(
            title="Save Security Report",
            defaultextension=extension,
            initialfile=(
                "hack-toolkit-report"
                + extension
            ),
            filetypes=[
                (
                    report_type.upper(),
                    "*" + extension
                )
            ]
        )

        if not path:
            return

        try:

            if report_type == "json":

                Path(path).write_text(
                    json.dumps(
                        self.results,
                        indent=2,
                        default=str
                    ),
                    encoding="utf-8"
                )

            elif report_type == "csv":

                with open(
                    path,
                    "w",
                    newline="",
                    encoding="utf-8"
                ) as file:

                    writer = csv.writer(
                        file
                    )

                    writer.writerow(
                        [
                            "Time",
                            "Target",
                            "Module",
                            "Data"
                        ]
                    )

                    for result in self.results:

                        writer.writerow(
                            [
                                result["time"],
                                result["target"],
                                result["module"],
                                json.dumps(
                                    result["data"],
                                    default=str
                                )
                            ]
                        )

            else:

                Path(path).write_text(
                    self.output.get(
                        "1.0",
                        "end"
                    ),
                    encoding="utf-8"
                )

            messagebox.showinfo(
                "Saved",
                f"Report saved:\n{path}"
            )

        except Exception as exc:

            messagebox.showerror(
                "Save Error",
                str(exc)
            )

    # ---------------------------------------------------------
    # CLEAR
    # ---------------------------------------------------------

    def clear_output(self):

        self.output.delete(
            "1.0",
            "end"
        )

        self.results.clear()

        self.log(
            "Output cleared."
        )


if __name__ == "__main__":

    application = HackToolkit()

    application.mainloop()
