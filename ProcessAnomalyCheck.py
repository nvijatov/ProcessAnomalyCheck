# Volatility 3 plugin that checks the parent process and execution path of critical Windows processes for anomalies.
#
#  Copyright (C) 2025 Nenad Vijatov
#
# Authors:
# Nenad Vijatov (nenad.vijatov@gmail.com)
#

import os
import datetime
import logging
from typing import Dict, List, Tuple

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class ProcessAnomalyCheck(interfaces.plugins.PluginInterface):
    """
    Checks the parent process and execution path of critical Windows processes for anomalies.
    """

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    EXPECTED_PROCESSES: Dict[str, Tuple[str, List[str]]] = {
        "svchost.exe": ("services.exe", ["C:\\Windows\\system32\\svchost.exe", "%SystemRoot%\\system32\\svchost.exe"]),
        "services.exe": ("wininit.exe", ["C:\\Windows\\system32\\services.exe", "%SystemRoot%\\system32\\services.exe"]),
        "lsaiso.exe": ("wininit.exe", ["C:\\Windows\\system32\\lsaiso.exe", "%SystemRoot%\\system32\\lsaiso.exe"]),
        "lsass.exe": ("wininit.exe", ["C:\\Windows\\system32\\lsass.exe", "%SystemRoot%\\system32\\lsass.exe"]),
        "explorer.exe": ("userinit.exe", ["C:\\Windows\\explorer.exe", "%SystemRoot%\\explorer.exe"]),
        "userinit.exe": ("winlogon.exe", ["C:\\Windows\\system32\\userinit.exe", "%SystemRoot%\\system32\\userinit.exe"]),
        "winlogon.exe": ("smss.exe", ["C:\\Windows\\system32\\winlogon.exe", "%SystemRoot%\\system32\\winlogon.exe"]),
        "csrss.exe": ("smss.exe", ["C:\\Windows\\system32\\csrss.exe", "%SystemRoot%\\system32\\csrss.exe"]),
        "wininit.exe": ("smss.exe", ["C:\\Windows\\system32\\wininit.exe", "%SystemRoot%\\system32\\wininit.exe"]),
    }

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        processes = {}
        for proc in pslist.PsList.list_processes(
            self.context, kernel.layer_name, kernel.symbol_table_name
        ):
            try:
                processes[proc.UniqueProcessId] = {
                    "name": proc.ImageFileName.cast(
                        "string", max_length=proc.ImageFileName.vol.count, errors="replace"
                    ),
                    "ppid": proc.InheritedFromUniqueProcessId,
                    "object": proc,
                }
            except exceptions.InvalidAddressException as e:
                vollog.debug(f"Error accessing process information: {e}")
                continue

        for pid, process_info in processes.items():
            process_name = process_info["name"]
            if process_name in self.EXPECTED_PROCESSES:
                expected_parent, expected_paths = self.EXPECTED_PROCESSES[process_name]
                parent_pid = process_info["ppid"]
                parent_process_name = processes.get(parent_pid, {}).get("name", "N/A")

                anomalies = []

                # Handle special cases for parent processes
                parent_anomaly = True
                if process_name == "wininit.exe" and parent_process_name == "N/A":
                    parent_anomaly = False
                elif process_name == "csrss.exe" and parent_process_name == "N/A":
                    parent_anomaly = False
                elif process_name == "explorer.exe" and parent_process_name == "N/A":
                    parent_anomaly = False
                elif process_name == "winlogon.exe" and parent_process_name == "N/A":
                    parent_anomaly = False
                elif process_name == "csrss.exe" and expected_parent == "smss.exe" and parent_process_name == "winlogon.exe":
                    parent_anomaly = False
                elif parent_process_name == expected_parent:
                    parent_anomaly = False

                if parent_anomaly:
                    anomalies.append(
                        f"Possible parent anomaly: Expected '{expected_parent}', found '{parent_process_name}' (PID: {parent_pid})"
                    )

                try:
                    peb = process_info["object"].get_peb()
                    if peb:
                        command_line = peb.ProcessParameters.CommandLine.get_string()
                        if command_line:
                            process_path = command_line.split('"')[1] if '"' in command_line else command_line.split()[0]
                            process_path_lower = process_path.lower()
                            path_match = False
                            system_root = os.environ.get("SystemRoot", "C:\\Windows").lower()

                            for expected_path_pattern in expected_paths:
                                expected_path_lower = expected_path_pattern.replace("%SystemRoot%", system_root).lower()
                                if process_path_lower == expected_path_lower:
                                    path_match = True
                                    break
                                # Also check if the retrieved path itself uses %SystemRoot%
                                expected_path_env_lower = expected_path_pattern.lower()
                                if process_path_lower == expected_path_env_lower:
                                    path_match = True
                                    break

                            if not path_match:
                                anomalies.append(
                                    f"Process path anomaly: Found '{process_path}'"
                                )
                        else:
                            anomalies.append("Could not retrieve full process path.")
                    else:
                        anomalies.append("Could not retrieve PEB object.")

                except exceptions.InvalidAddressException as e:
                    anomalies.append(f"Error retrieving process path: {e}")
                except AttributeError:
                    anomalies.append("Could not retrieve process path information.")

                if anomalies:
                    yield (
                        0,
                        (
                            process_name,
                            pid,
                            parent_process_name,
                            parent_pid,
                            "\n".join(anomalies),
                        ),
                    )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Process Name", str),
                ("PID", int),
                ("Parent Process Name", str),
                ("Parent PID", int),
                ("Anomalies", str),
            ],
            self._generator(),
        )