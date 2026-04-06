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
	while line := await reader.readline():
		[cmd, *args] = line.decode().strip().split()
		if cmd == "auth":
			# Needs one argument: 2FA code.
			if pyotp.TOTP("JBSWY3DPEHPK3PXP", 8).verify(args[0] if args else ""):
				writer.write(b"login ok\n");
				await writer.drain()

async def main():
	print("I am", os.getpid())
	await asyncio.start_unix_server(client, "/tmp/certmgr")
	await asyncio.Future()

asyncio.run(main())
