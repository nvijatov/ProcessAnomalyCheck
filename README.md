# ProcessAnomalyCheck Volatility 3 Plugin

## Description

The `ProcessAnomalyCheck` plugin for Volatility 3 is designed to identify potential anomalies in critical Windows processes by verifying their parent process and execution path against expected values for standard Windows 10/11 installations.

The plugin checks the following processes:
* `svchost.exe`
* `services.exe`
* `lsaiso.exe`
* `lsass.exe`
* `explorer.exe`
* `userinit.exe`
* `winlogon.exe`
* `csrss.exe`
* `wininit.exe`

For each of these processes found in the memory image, the plugin attempts to determine its parent process and its full execution path. It then compares these against a set of predefined expected values. Any discrepancies are reported as potential anomalies, highlighting processes that might have been started unusually or from unexpected locations.

The plugin includes specific handling for known Windows behaviors, such as processes like `wininit.exe`, `csrss.exe`, `explorer.exe`, and `winlogon.exe` potentially appearing without a parent if their creating process (`smss.exe` or `userinit.exe`) has already exited. It also accounts for `%SystemRoot%` in process paths.

## Installation

To install the `ProcessAnomalyCheck` plugin, you need to place the plugin file (`processanomalycheck.py`) in the appropriate Volatility 3 plugin directory.

1.  **Save the code:** Save the Python code provided to you as `processanomalycheck.py`.
2.  **Locate Volatility 3 plugin directory:** The standard location for third-party plugins is typically within the `volatility3/plugins/windows/` directory relative to where Volatility 3 is installed or cloned.
    * If you installed Volatility 3 using pip, you might find the directory within your Python site-packages.
    * If you cloned the Volatility 3 repository from source, it will be within the cloned directory structure.
    * You can also configure Volatility 3 to load plugins from a custom directory by using the `--plugins` option when running `vol.py`.
3.  **Place the file:** Copy the `processanomalycheck.py` file into the `volatility3/plugins/windows/` directory or your designated custom plugin directory.

After placing the file, Volatility 3 should automatically detect the new plugin the next time it is run. You can verify this by running `vol.py --info` and looking for `windows.processanomalycheck` in the list of available plugins.

## Usage

To run the `ProcessAnomalyCheck` plugin, use the following command syntax:

```bash
python3 vol.py -f <path_to_memory_image> windows.processanomalycheck
