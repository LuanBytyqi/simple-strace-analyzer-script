import subprocess
import sys
import os

"""
strace-wrapper.py – extracts network and file activity from ELF-Executables
Usage: python3 strace-wrapper.py path/to/executable
"""

arguments = sys.argv

if len(arguments) <= 1:
    print("No file path provided")
    sys.exit(1) # end

if len(arguments) > 2:
    print("Too many arguments")
    sys.exit(1) #end

env = os.environ.copy()

# Magic ELF-Bytes
magic_numbers_elf = {'ELF': bytes([0x7f, 0x45, 0x4c, 0x46])}

filepath = arguments[1]

try:
    #To make sure you can only analyze linux elf binaries
    with open(filepath, "rb") as fd:
        file_header = fd.read(4)
        if not file_header.startswith(magic_numbers_elf['ELF']):
            print("Provided Binary isn't a Linux executable")
            sys.exit(1)
except FileNotFoundError:
    print(f"File or Directory at '{filepath}' doesn't exist")
    sys.exit(1)
except Exception as e:
    print(f"Unexpected Error: {e}")
    sys.exit(1)

result_string = "" # The final Output-String
# script_name = arguments[0] # not used
file_name = os.path.basename(filepath) # Name of the file to analyze



# Using strace and stdout as well as stderr.
# Since it is only allowed to use strace once, we'll have to put everything in the same output (stderr)
try:
    pipe = subprocess.Popen(["strace","-e","trace=network,file",filepath], stdout = subprocess.PIPE, stderr=subprocess.PIPE, env=env)
except FileNotFoundError:
    print(f"Error: File '{filepath}' not found")
    sys.exit(1)
except PermissionError:
    print(f"Error: File '{filepath}' is not executable")
    sys.exit(1)
except Exception as e:
    print(f"Unexpected error: {e}")
    sys.exit(1)

# res = tuple (stdout, stderr)
stdout, stderr = pipe.communicate()
#error = pipe.returncode # not used

network_syscalls = [
    "socket",
    "connect",
    "accept",
    "bind",
    "listen",
    "send",
    "sendto",
    "sendmsg",
    "recv",
    "recvfrom",
    "recvmsg",
    "shutdown",
    "getsockname",
    "getpeername",
    "setsockopt",
    "getsockopt"
]

file_syscalls = [

    "open", "openat", "creat", "close", "dup", "dup2", "dup3",

    "read", "write", "pread", "pwrite", "readv", "writev",

    "stat", "fstat", "lstat", "chmod", "fchmod", "chown", "fchown",
    "truncate", "ftruncate", "access", "lseek",

    "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat", "rename", "renameat", "chdir", "fchdir", "getdents",
    "getdents64",

    "fsync", "fdatasync", "mmap", "munmap"
]

network_lines = []
file_lines = []

# Our own parsing of the Output (stderr)
for line in stderr.decode(errors="replace").splitlines():
    # Saving all network-related activity
    if any(call in line for call in network_syscalls):
        network_lines.append(line)
    # Saving all file-related activity
    elif any(call in line for call in file_syscalls):
        file_lines.append(line)

# Saving all environmental activity from env dict to a list that later gets put together
all_env_vars = [f"{k}={v}" for k, v in env.items()]

# FILENAME
result_string = "FILENAME: \n"+file_name+"\n"

result_string = result_string + "\n"

# OUTPUT TO STDOUT
temp = stdout.decode(errors="replace")
if temp == "" or len(temp) < 1:
    result_string = result_string + "OUTPUT TO STDOUT:\n" + "Nothing in Standard Output" + "\n"
else:
    result_string = result_string + "OUTPUT TO STDOUT:" + temp + "\n"

result_string = result_string + "\n"

# CONNECTIONS
result_string = result_string + "CONNECTIONS:\n"
all_connections = "\n".join(network_lines)
if all_connections == "":
    result_string = result_string + "No Network Activity" + "\n"
else:
    result_string = result_string +all_connections+"\n"

result_string = result_string + "\n"

# ACCESSED FILES
result_string = result_string + "ACCESSED FILES:\n"
all_files = "\n".join(file_lines)
if all_files == "":
    result_string = result_string +"No File Activity" + "\n"
else:
    result_string = result_string+ all_files + "\n"

result_string = result_string + "\n"

#ENVIRONMENT
result_string = result_string + "ENVIRONMENT:\n"
all_environments = "\n".join(all_env_vars)
if all_environments == "":
    result_string = result_string +"No Environment Variables" + "\n"
else:
    result_string = result_string +all_environments+"\n"

print(result_string)



