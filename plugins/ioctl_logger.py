"""
# IOCTL Logger Plugin

This plugin hooks and logs all ioctl system calls with their arguments and return values.
It captures ioctl commands, file descriptors, argument structures, and logs them to both
the console and a file for debugging and analysis purposes. Additionally, it supports
modifying ioctl return values based on configurable rules.

## Purpose

- Monitors all ioctl system calls (entry and return).
- Decodes common ioctl commands and their argument structures.
- Modifies ioctl return values based on configurable rules.
- Logs to both console and file for comprehensive tracking.
- Provides detailed information about ioctl operations for security analysis.

## Modification Rule Structure

Each modification rule is a dictionary with two main components:

### Match Criteria (all optional, matched with AND logic):
- `pid`: Exact process ID to match
- `process_name`: Process name substring to match (e.g., "bash" matches "bash", "/bin/bash")
- `fd`: Exact file descriptor number to match
- `fd_name`: File descriptor name substring to match (e.g., "socket", "/dev/tty")
- `cmd`: IOCTL command - can be:
  - String name from IOCTL_COMMANDS dict (e.g., "TIOCGWINSZ")
  - Integer command number (e.g., 0x5413)
- `type`: IOCTL type field (bits 15-8 of command) as hex string or int
- `number`: IOCTL number field (bits 7-0 of command) as hex string or int
- `arg`: Exact argument pointer value to match
- `custom_match`: Function(pid, proc_name, fd, fd_name, cmd, arg) -> bool (programmatic only)

### Action to Take (use one):
- `return_value`: Set specific return value (e.g., 0 for success, -1 for failure)
- `errno`: Set errno value (will be returned as negative, e.g., errno=22 returns -22)
- `custom_action`: Function(original_retval, syscall, entry) -> new_retval (programmatic only)

## Common Use Cases

### 1. Security Testing - Simulating Permission Errors
```yaml
modifications:
  - match:
      process_name: "untrusted"
      type: "0x89"  # Network ioctls
    action:
      errno: 13  # EACCES
```

### 2. Fault Injection - Testing Error Handling
```yaml
modifications:
  - match:
      cmd: "SIOCGIFADDR"
    action:
      errno: 19  # ENODEV - simulate missing network device
```

### 3. Behavior Modification - Forcing Success
```yaml
modifications:
  - match:
      process_name: "legacy_app"
      cmd: "TCGETS"
    action:
      return_value: 0  # Always succeed
```

### 4. Blocking Operations
```yaml
modifications:
  - match:
      process_name: "suspicious"
      cmd: "SIOCGIFHWADDR"  # Getting MAC address
    action:
      errno: 1  # EPERM - operation not permitted
```

## Arguments

- `outdir`: Output directory for the log file (optional).
- `verbose`: Enable verbose debug logging (optional, default: False).
- `quiet`: Disable all output that is not an ERROR (optional, default: False)
- `procs`: List of process names to filter ioctl logging (optional).
- `modifications`: List of modification rules for changing ioctl return values (optional).

## Output

The plugin produces two types of output:

1. **Console Logs**: Real-time ioctl events with basic information
   ```
   IOCTL ENTER: bash[1234] ioctl(fd:0, TCGETS, 0x7ffe123)
   IOCTL MODIFY: Matched rule for bash[1234] ioctl(fd:0, TCGETS)
   IOCTL RETURN: bash[1234] ioctl(fd:0, TCGETS) = 0 [SUCCESS]
   ```

2. **JSON Log File** (`ioctl_log.jsonl`): Detailed records including:
   - Timestamp
   - Process information (name, PID, arguments, environment)
   - File descriptor details
   - IOCTL command breakdown (type, number, direction, size)
   - Original and modified return values
   - Modification rules that were applied

## Notes

- Custom match and action functions (`custom_match`, `custom_action`) can only be used
  in programmatic configuration, not in YAML files.
- When using YAML configuration, all numeric values in match criteria can be specified
  as either decimal integers or hex strings (e.g., 0x5413 or "0x5413").
- Process name and FD name matching uses substring matching (partial match).
- All match criteria in a rule must match for the rule to apply (AND logic).
- Only the first matching rule is applied to each ioctl.
- Modifications happen at the kernel/syscall level, so the target process sees the
  modified return value.

"""

import os
import json
from datetime import datetime
from penguin import Plugin, plugins

# Common IOCTL commands (from Linux headers)
IOCTL_COMMANDS = {
    # Terminal IOCTLs
    0x5401: "TCGETS",
    0x5402: "TCSETS",
    0x5403: "TCSETSW",
    0x5404: "TCSETSF",
    0x5405: "TCGETA",
    0x5406: "TCSETA",
    0x5407: "TCSETAW",
    0x5408: "TCSETAF",
    0x5409: "TCSBRK",
    0x540A: "TCXONC",
    0x540B: "TCFLSH",
    0x540C: "TIOCEXCL",
    0x540D: "TIOCNXCL",
    0x540E: "TIOCSCTTY",
    0x540F: "TIOCGPGRP",
    0x5410: "TIOCSPGRP",
    0x5411: "TIOCOUTQ",
    0x5412: "TIOCSTI",
    0x5413: "TIOCGWINSZ",
    0x5414: "TIOCSWINSZ",
    0x5415: "TIOCMGET",
    0x5416: "TIOCMBIS",
    0x5417: "TIOCMBIC",
    0x5418: "TIOCMSET",
    0x5419: "TIOCGSOFTCAR",
    0x541A: "TIOCSSOFTCAR",

    # File IOCTLs
    0x125D: "BLKGETSIZE",
    0x1260: "BLKGETSIZE64",
    0x1261: "BLKFLSBUF",
    0x1262: "BLKRASET",
    0x1263: "BLKRAGET",
    0x1264: "BLKFRASET",
    0x1265: "BLKFRAGET",
    0x1266: "BLKSECTSET",
    0x1267: "BLKSECTGET",
    0x1268: "BLKSSZGET",

    # Network IOCTLs
    0x8910: "SIOCGIFNAME",
    0x8911: "SIOCSIFLINK",
    0x8912: "SIOCGIFCONF",
    0x8913: "SIOCGIFFLAGS",
    0x8914: "SIOCSIFFLAGS",
    0x8915: "SIOCGIFADDR",
    0x8916: "SIOCSIFADDR",
    0x8917: "SIOCGIFDSTADDR",
    0x8918: "SIOCSIFDSTADDR",
    0x8919: "SIOCGIFBRDADDR",
    0x891A: "SIOCSIFBRDADDR",
    0x891B: "SIOCGIFNETMASK",
    0x891C: "SIOCSIFNETMASK",
    0x891D: "SIOCGIFMETRIC",
    0x891E: "SIOCSIFMETRIC",
    0x891F: "SIOCGIFMEM",
    0x8920: "SIOCSIFMEM",
    0x8921: "SIOCGIFMTU",
    0x8922: "SIOCSIFMTU",
    0x8923: "SIOCSIFNAME",
    0x8924: "SIOCSIFHWADDR",
    0x8925: "SIOCGIFENCAP",
    0x8926: "SIOCSIFENCAP",
    0x8927: "SIOCGIFHWADDR",
    0x8929: "SIOCGIFSLAVE",
    0x8930: "SIOCSIFSLAVE",
    0x8931: "SIOCADDMULTI",
    0x8932: "SIOCDELMULTI",
    0x8933: "SIOCGIFINDEX",
    0x8970: "SIOCGSTAMP",
    0x89F0: "SIOCDEVPRIVATE",
}


class IoctlLogger(Plugin):
    """
    Plugin for logging ioctl system calls to both console and file.
    """

    def __init__(self, panda) -> None:
        """
        Initialize the IoctlLogger plugin.

        **Parameters:**
        - `panda`: The PANDA instance.

        **Returns:** None
        """
        self.outdir = self.get_arg("outdir")
        self.verbose = self.get_arg_bool("verbose")
        self.quiet = self.get_arg_bool("quiet")
        self.procs = self.get_arg("procs")
        self.modifications = self.get_arg("modifications")

        # Create log file
        self.log_file_path = os.path.join(self.outdir, "ioctl_log.jsonl")
        self.log_file = open(self.log_file_path, "w", buffering=1)  # Line buffered

        if self.verbose:
            self.logger.setLevel("DEBUG")

        if self.quiet:
            self.logger.setLevel("ERROR")

        self.logger.info(f"IOCTL logging initialized. Log file: {self.log_file_path}")

        # Store pending ioctl calls (keyed by asid+pc to handle concurrent calls)
        self.pending_ioctls = {}

        # Parse modification rules if provided
        self.modification_rules = []
        if self.modifications:
            for mod in self.modifications:
                # Each modification rule should be a dict with:
                # - match: dict with criteria (pid, process_name, fd, fd_name, cmd, type, number, etc.)
                # - action: dict with action to take (return_value, errno, etc.)
                self.modification_rules.append(mod)
                self.logger.info(f"Added ioctl modification rule: {mod}")

        # Hook ioctl enter and return
        if self.procs:
            for proc in self.procs:
                plugins.syscalls.syscall("on_sys_ioctl_enter", comm_filter=proc)(
                    self.ioctl_enter)
                plugins.syscalls.syscall("on_sys_ioctl_return", comm_filter=proc)(
                    self.ioctl_return)
        else:
            plugins.syscalls.syscall("on_sys_ioctl_enter")(self.ioctl_enter)
            plugins.syscalls.syscall("on_sys_ioctl_return")(self.ioctl_return)

    def match_modification_rule(self, rule: dict, pid: int, proc_name: str, fd: int,
                                 fd_name: str, cmd_int: int, cmd_info: dict,
                                 arg: int) -> bool:
        """
        Check if the given ioctl matches a modification rule.

        **Parameters:**
        - `rule` (`dict`): The modification rule to check.
        - `pid` (`int`): Process ID.
        - `proc_name` (`str`): Process name.
        - `fd` (`int`): File descriptor.
        - `fd_name` (`str`): File descriptor name.
        - `cmd_int` (`int`): IOCTL command as integer.
        - `cmd_info` (`dict`): Decoded command information.
        - `arg` (`int`): Argument pointer.

        **Returns:** `bool` - True if the rule matches, False otherwise
        """
        match_criteria = rule.get("match", {})

        # Check PID match
        if "pid" in match_criteria:
            if match_criteria["pid"] != pid:
                return False

        # Check process name match (supports partial match)
        if "process_name" in match_criteria:
            if match_criteria["process_name"] not in proc_name:
                return False

        # Check FD match
        if "fd" in match_criteria:
            if match_criteria["fd"] != fd:
                return False

        # Check FD name match (supports partial match)
        if "fd_name" in match_criteria:
            if match_criteria["fd_name"] not in fd_name:
                return False

        # Check command match (can be number or name)
        if "cmd" in match_criteria:
            cmd_match = match_criteria["cmd"]
            if isinstance(cmd_match, str):
                # Match by name
                if cmd_match != cmd_info["name"]:
                    return False
            else:
                # Match by number
                if cmd_match != cmd_int:
                    return False

        # Check IOCTL type field
        if "type" in match_criteria:
            type_val = int(match_criteria["type"], 16) if isinstance(match_criteria["type"], str) else match_criteria["type"]
            if type_val != int(cmd_info["type"], 16):
                return False

        # Check IOCTL number field
        if "number" in match_criteria:
            num_val = int(match_criteria["number"], 16) if isinstance(match_criteria["number"], str) else match_criteria["number"]
            if num_val != int(cmd_info["number"], 16):
                return False

        # Check arg value (if specified)
        if "arg" in match_criteria:
            if match_criteria["arg"] != arg:
                return False

        # Check for custom matching function
        if "custom_match" in match_criteria:
            # This allows for more complex matching logic
            try:
                if not match_criteria["custom_match"](pid, proc_name, fd, fd_name, cmd_int, arg):
                    return False
            except Exception as e:
                self.logger.warning(f"Custom match function failed: {e}")
                return False

        # All criteria matched
        return True

    def decode_ioctl_cmd(self, cmd: int) -> dict:
        """
        Decode an ioctl command number into its components.

        **Parameters:**
        - `cmd` (`int`): The ioctl command number.

        **Returns:** `dict` with decoded command information
        """
        # IOCTL command encoding (Linux):
        # bits 31-30: direction (00=none, 01=write, 10=read, 11=read/write)
        # bits 29-16: size
        # bits 15-8: type
        # bits 7-0: number

        direction = (cmd >> 30) & 0x3
        size = (cmd >> 16) & 0x3FFF
        ioc_type = (cmd >> 8) & 0xFF
        number = cmd & 0xFF

        dir_map = {
            0: "NONE",
            1: "WRITE",
            2: "READ",
            3: "READ/WRITE"
        }

        return {
            "raw": f"{cmd:#x}",
            "name": IOCTL_COMMANDS.get(cmd, f"UNKNOWN_{cmd:#x}"),
            "direction": dir_map[direction],
            "size": size,
            "type": f"{ioc_type:#x}",
            "number": f"{number:#x}"
        }

    def format_arg_data(self, arg: int, cmd_info: dict) -> str:
        """
        Format the argument data based on the ioctl command.

        **Parameters:**
        - `arg` (`int`): The argument pointer.
        - `cmd_info` (`dict`): Decoded command information.

        **Returns:** `str` formatted argument representation
        """
        if arg == 0:
            return "NULL"

        # For known commands, try to decode the structure
        cmd_name = cmd_info["name"]

        # Basic formatting for now - can be extended for specific structures
        if "SIOCGIF" in cmd_name or "SIOCSIF" in cmd_name:
            # Network interface request - has interface name at start
            try:
                iface_name = yield from plugins.mem.read_str(arg, max_len=16)
                return f"{arg:#x}(iface={iface_name})"
            except:
                pass

        # Default: just show pointer and size if available
        size = cmd_info["size"]
        if size > 0 and size < 256:  # Reasonable size
            try:
                data = yield from plugins.mem.read(arg, size)
                hex_str = data.hex() if data else "empty"
                if len(hex_str) > 32:
                    hex_str = hex_str[:32] + "..."
                return f"{arg:#x}(size={size}, data={hex_str})"
            except:
                pass

        return f"{arg:#x}"

    def ioctl_enter(self, regs, proto, syscall, fd, cmd, arg) -> None:
        """
        Hook for ioctl syscall entry.

        **Parameters:**
        - `regs`: Register/context object.
        - `proto`: Syscall prototype.
        - `syscall`: Syscall object.
        - `fd`: File descriptor.
        - `cmd`: IOCTL command.
        - `arg`: Argument pointer.

        **Returns:** None
        """
        # Get process information using OSI
        proc = yield from plugins.osi.get_proc()
        proc_name = proc.name if proc else "unknown"
        pid = proc.pid if proc else 0

        # Get process arguments
        proc_args = yield from plugins.osi.get_args()

        # Get process environment
        proc_env = yield from plugins.osi.get_env()

        # Get file descriptor name
        fd_name = yield from plugins.osi.get_fd_name(fd)
        if not fd_name:
            fd_name = f"fd:{fd}"

        # Get all file descriptors for this process (for context)
        all_fds = yield from plugins.osi.get_fds(pid=pid)
        fds_info = []
        for fd_obj in all_fds[:10]:  # Limit to first 10 FDs for brevity
            fds_info.append({"fd": fd_obj.fd, "name": fd_obj.name})

        # Decode the command
        cmd_int = int(self.panda.ffi.cast("unsigned int", cmd))
        cmd_info = self.decode_ioctl_cmd(cmd_int)

        # Format argument
        arg_int = int(self.panda.ffi.cast("target_ulong", arg))
        arg_repr = yield from self.format_arg_data(arg_int, cmd_info)

        # Check if this ioctl should be modified
        modification_rule = None
        for rule in self.modification_rules:
            if self.match_modification_rule(rule, pid, proc_name, fd, fd_name,
                                             cmd_int, cmd_info, arg_int):
                modification_rule = rule
                self.logger.info(f"IOCTL MODIFY: Matched rule for {proc_name}[{pid}] ioctl({fd_name}, {cmd_info['name']})")
                if self.verbose:
                    self.logger.debug(f"  Rule: {rule}")
                break

        # Create entry record
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "ioctl_enter",
            "process": proc_name,
            "pid": pid,
            "fd": fd,
            "fd_name": fd_name,
            "cmd": cmd_info,
            "arg": arg_repr,
            "proc_args": proc_args,
            "proc_env": dict(list(proc_env.items())[:5]) if proc_env else {},  # Limit env vars for brevity
            "open_fds": fds_info,
            "modification_rule": modification_rule  # Store the rule if matched
        }

        # Store for matching with return - use pid and fd as key
        key = f"{pid}_{fd}_{cmd_int}"
        self.pending_ioctls[key] = entry

        # Log to console
        self.logger.info(f"IOCTL ENTER: {proc_name}[{pid}] ioctl({fd_name}, {cmd_info['name']}, {arg_repr})")
        if self.verbose:
            self.logger.debug(f"  Process args: {proc_args}")
            self.logger.debug(f"  Open FDs: {len(all_fds)} total")

        # Log to file
        self.log_file.write(json.dumps(entry) + "\n")

    def ioctl_return(self, regs, proto, syscall, fd, cmd, arg) -> None:
        """
        Hook for ioctl syscall return.

        **Parameters:**
        - `regs`: Register/context object.
        - `proto`: Syscall prototype.
        - `syscall`: Syscall object.
        - `fd`: File descriptor.
        - `cmd`: IOCTL command.
        - `arg`: Argument pointer.

        **Returns:** None
        """
        # Get process info to reconstruct the key
        proc = yield from plugins.osi.get_proc()
        pid = proc.pid if proc else 0
        cmd_int = int(self.panda.ffi.cast("unsigned int", cmd))

        # Get matching entry
        key = f"{pid}_{fd}_{cmd_int}"
        entry = self.pending_ioctls.pop(key, None)

        # Get original return value
        original_retval = int(self.panda.ffi.cast("target_long", syscall.retval))
        retval = original_retval

        # Check if we need to apply a modification
        if entry and entry.get("modification_rule"):
            rule = entry["modification_rule"]
            action = rule.get("action", {})

            # Apply the modification
            if "return_value" in action:
                new_retval = int(action["return_value"])  # Ensure it's an integer
                # Set the new return value directly as an integer
                syscall.retval = new_retval
                retval = new_retval
                self.logger.info(f"IOCTL MODIFIED: Changed return value from {original_retval} to {new_retval}")

            # Apply errno modification (negative return value)
            elif "errno" in action:
                errno_val = int(action["errno"])  # Ensure it's an integer
                new_retval = -errno_val  # Return negative errno
                syscall.retval = new_retval
                retval = new_retval
                self.logger.info(f"IOCTL MODIFIED: Set errno {errno_val} (return {new_retval})")

            # Apply custom modification function
            elif "custom_action" in action:
                try:
                    new_retval = action["custom_action"](original_retval, syscall, entry)
                    new_retval = int(new_retval)  # Ensure it's an integer
                    syscall.retval = new_retval
                    retval = new_retval
                    self.logger.info(f"IOCTL MODIFIED: Custom action changed return from {original_retval} to {new_retval}")
                except Exception as e:
                    self.logger.warning(f"Custom action function failed: {e}")
                    retval = original_retval

        # Get process information (in case it wasn't captured on entry)
        if not entry:
            proc = yield from plugins.osi.get_proc()
            proc_name = proc.name if proc else "unknown"
            pid = proc.pid if proc else 0

            fd_name = yield from plugins.osi.get_fd_name(fd)
            if not fd_name:
                fd_name = f"fd:{fd}"

            cmd_int = int(self.panda.ffi.cast("unsigned int", cmd))
            cmd_info = self.decode_ioctl_cmd(cmd_int)
        else:
            proc_name = entry["process"]
            pid = entry["pid"]
            fd_name = entry["fd_name"]
            cmd_info = entry["cmd"]

        # Determine if it was successful
        success = retval >= 0
        error_str = ""
        if not success:
            # Map error code if negative
            errnum = -retval
            error_str = f" (errno={errnum})"

        # For return, also capture any changes to the argument buffer
        arg_int = int(self.panda.ffi.cast("target_ulong", arg))
        arg_repr_after = yield from self.format_arg_data(arg_int, cmd_info)

        # Create return record
        ret_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "ioctl_return",
            "process": proc_name,
            "pid": pid,
            "fd": fd,
            "fd_name": fd_name,
            "cmd": cmd_info,
            "arg_after": arg_repr_after,
            "retval": retval,
            "success": success,
            "error": error_str if error_str else None
        }

        # Add modification info if applicable
        if entry and entry.get("modification_rule"):
            ret_entry["modified"] = True
            ret_entry["original_retval"] = original_retval
            ret_entry["modification_rule"] = entry["modification_rule"]

        # Log to console
        status = "SUCCESS" if success else f"FAILED{error_str}"
        self.logger.info(f"IOCTL RETURN: {proc_name}[{pid}] ioctl({fd_name}, {cmd_info['name']}) = {retval} [{status}]")

        if self.verbose and not success:
            self.logger.debug(f"  Command details: {cmd_info}")
            self.logger.debug(f"  Arg after: {arg_repr_after}")

        # Log to file
        self.log_file.write(json.dumps(ret_entry) + "\n")

    def uninit(self) -> None:
        """
        Clean up resources when plugin is unloaded.

        **Returns:** None
        """
        if hasattr(self, 'log_file'):
            self.log_file.close()
            self.logger.info(f"IOCTL log saved to: {self.log_file_path}")
