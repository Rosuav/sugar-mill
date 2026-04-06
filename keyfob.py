# Run this as root to make certificates and their private keys available
import os
import socket
import asyncio
import pyotp

def getsockopt(fd, level, opt):
	sock = socket.socket(fileno=fd)
	try: return sock.getsockopt(level, opt)
	finally: sock.detach() # Detach even if we hit an error of some sort

async def client(reader, writer):
	print("Got connection, sock is", writer.get_extra_info("sock"))
	fd = reader._transport._sock_fd
	pid = getsockopt(fd, socket.SOL_SOCKET, socket.SO_PEERCRED);
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
