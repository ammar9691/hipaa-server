#!/usr/bin/env python3
"""Stream a local bash script to `sudo bash -s` on an alias from servers.json and print output.
Usage: python run_script.py @alias script.sh [timeout_seconds]
servers.json: {"alias": {"host": "...", "user": "...", "key": "/path/key.pem"}}; path via SERVERS_JSON env.
"""
import json
import os
import sys

import paramiko

STORE = os.environ.get("SERVERS_JSON", os.path.join(os.path.dirname(os.path.abspath(__file__)), "servers.json"))

alias = sys.argv[1].lstrip("@")
script = open(sys.argv[2], "rb").read().replace(b"\r\n", b"\n")
timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 1800

s = json.load(open(STORE, encoding="utf-8"))[alias]
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
kw = dict(hostname=s["host"], port=int(s.get("port", 22)), username=s.get("user", "root"),
          timeout=30, allow_agent=False, look_for_keys=False)
if s.get("key"):
    kw["key_filename"] = s["key"]
else:
    kw["password"] = s["password"]
c.connect(**kw)
c.get_transport().set_keepalive(15)
stdin, stdout, stderr = c.exec_command("sudo bash -s 2>&1", timeout=timeout)
stdin.write(script)
stdin.channel.shutdown_write()
for line in iter(stdout.readline, ""):
    sys.stdout.buffer.write(line.encode("utf-8", "replace"))
    sys.stdout.buffer.flush()
rc = stdout.channel.recv_exit_status()
c.close()
print(f"[remote rc={rc}]")
sys.exit(rc)
