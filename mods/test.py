### ./mods/uname.py
import asyncio
import shlex

# --- Module Metadata ---
description = "Returns kernel information (uname)."

async def execute(args_string: str):
    """
    Executes the 'uname' command with the provided arguments.
    """
    command = "uname"
    args_list = shlex.split(args_string)
    
    proc = await asyncio.create_subprocess_exec(
        command,
        *args_list,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode == 0:
        return stdout.decode().strip()
    else:
        error_msg = stderr.decode().strip()
        return f"Error executing '{command} {args_string}': {error_msg}"
