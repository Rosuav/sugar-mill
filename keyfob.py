# Run this as root to make certificates and their private keys available
import os
import socket
import asyncio
import pyotp

async def client(reader, writer):
	pid = writer.get_extra_info("socket").getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED);
	print("Connection from", pid)
	writer.write(b"hello\n")
	await writer.drain()
	logged_in = False
	while line := await reader.readline():
		[cmd, *args] = line.decode().strip().split()
		if cmd == "auth":
			# Needs one argument: 2FA code.
			if pyotp.TOTP("JBSWY3DPEHPK3PXP", 8).verify(args[0] if args else ""):
				writer.write(b"login ok\n")
				await writer.drain()
				logged_in = True
		elif not logged_in:
			writer.write(b"error Not logged in\n")
			await writer.drain()
			continue
		if cmd == "fetch":
			if not args:
				writer.write(b"error Need a file name\n")
				await writer.drain()
				continue
			fn = args[0]
			if fn not in ("db.rosuav.com", "stillebot.com", "sikorsky.stillebot.com", "gideon.stillebot.com"):
				writer.write(b"error Unknown file requested\n")
				await writer.drain()
				continue
			pem = key = None
			try:
				with open(fn + ".pem", "rb") as p, open(fn + ".key", "rb") as k:
					pem = p.read()
					key = k.read()
			except FileNotFoundError:
				writer.write(b"error File not found\n") # Valid name but not on this system
				await writer.drain()
				continue
			except Exception as e:
				writer.write(b"error Unexpected " + type(e).__name__.encode() + b"\n")
				await writer.drain()
				continue
			if not pem.endswith(b"\n"): pem += b"\n"
			if not key.endswith(b"\n"): key += b"\n"
			if b"\n.\n" in pem or b"\n.\n" in key:
				# The other end doesn't have handling for this, but it really shouldn't happen
				pem = key = b"INVALID CONTENT"
			writer.write(b"privkey " + fn.encode() + b"\n")
			writer.write(key)
			writer.write(b".\n")
			writer.write(b"certificate " + fn.encode() + b"\n")
			writer.write(pem)
			writer.write(b".\n")
			# At this point, we've sent the file requested, but we also know that this client finds
			# this file to be useful. It MAY be worth holding onto that information and sending the
			# updated cert/key when it becomes available. The client will react accordingly and can
			# reconnect to whatever's needed.

async def main():
	print("I am", os.getpid())
	await asyncio.start_unix_server(client, "/tmp/certmgr")
	await asyncio.Future()

asyncio.run(main())
