# Run this as root to make certificates and their private keys available
import os
import hashlib
import socket
import sys
import asyncio
import pyotp

AVAILABLE_CERTS = {
	"db.rosuav.com": ("db.rosuav.com.pem", "db.rosuav.com.key"),
	"stillebot.com": ("/etc/letsencrypt/live/stillebot.com/fullchain.pem", "/etc/letsencrypt/live/stillebot.com/privkey.pem"),
	"sikorsky.stillebot.com": ("/etc/letsencrypt/live/sikorsky.rosuav.com/fullchain.pem", "/etc/letsencrypt/live/sikorsky.rosuav.com/privkey.pem"),
	"gideon.stillebot.com": ("/etc/letsencrypt/live/gideon.rosuav.com/fullchain.pem", "/etc/letsencrypt/live/gideon.rosuav.com/privkey.pem"),
}
totp = None
clients = []
cert_hash = { } # Map a cert name to its SHA1 to recognize changes

async def poker():
	with open("fullchain44.pem", "rb") as p, open("privkey44.pem", "rb") as k:
		cert = p.read() + k.read()
	while True:
		await asyncio.sleep(0.5)
		for cli in clients:
			if "stillebot.com" in cli[1] and "hack_done" not in cli[1]:
				cli[1].append("hack_done")
				print("Sending hack")
				cli[0].write(b"certificate %s\n%s.\n" % ("stillebot.com".encode(), cert))

def rescan_certs():
	print("Rescan certs")
	for cert, hash in cert_hash.items():
		print(cert, hash)

async def client(reader, writer):
	cli = (writer, [])
	try:
		clients.append(cli)
		pid = writer.get_extra_info("socket").getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED);
		print("Connection from", pid)
		writer.write(b"hello\n")
		await writer.drain()
		logged_in = False
		while line := await reader.readline():
			[cmd, *args] = line.decode().strip().split()
			if cmd == "reload":
				# Magic reload signal, does not require login as long as the other end
				# is a root-owned process.
				# NOTE: I could probably do better by reading /proc/{pid}/status and
				# parsing it out, but os.stat on the proc-pid directory itself gives
				# the same information more conveniently.
				if os.stat("/proc/%d" % pid).st_uid == 0:
					rescan_certs()
					break # Message received, goodbye
				# Otherwise fall through, pretending that this command doesn't exist
			if cmd == "auth":
				# Needs two argument: user, 2FA code.
				# Currently the user is not used and should always be "sugar".
				# Maybe in the future there'll be different users with different perms.
				if len(args) != 2: continue
				if args[0] != "sugar": continue
				if totp.verify(args[1]):
					print("Authenticated", pid)
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
				if fn not in AVAILABLE_CERTS:
					writer.write(b"error Unknown file requested\n")
					await writer.drain()
					continue
				cert = b""
				try:
					for f in AVAILABLE_CERTS[fn]:
						print(f)
						with open(f, "rb") as f:
							cert += f.read()
				except FileNotFoundError:
					writer.write(b"error File not found\n") # Valid name but not on this system
					await writer.drain()
					continue
				except Exception as e:
					writer.write(b"error Unexpected " + type(e).__name__.encode() + b"\n")
					await writer.drain()
					continue
				if b"\n.\n" in cert:
					# The other end doesn't have handling for this, but it really shouldn't happen
					cert = b"INVALID CONTENT\n"
				writer.write(b"certificate %s\n%s.\n" % (fn.encode(), cert))
				# At this point, we've sent the file requested, but we also know that this client finds
				# this file to be useful. Track that this client wants this cert; and also quickly hash
				# the cert so we can see when it changes.
				cli[1].append(fn)
				hash = hashlib.sha1(cert).hexdigest()
				if fn in cert_hash:
					if cert_hash[fn] != hash: rescan_certs() # TODO: Simplify this (just send out the one cert)
				else:
					cert_hash[fn] = hash
			elif cmd == "ping":
				writer.write(b"pong\n")
				await writer.drain()
	finally:
		try: clients.remove(cli)
		except ValueError: pass # In the unlikely case that we crash before appending self, don't replace the exception

# The live key fob has its socket in /var/run, which only root can bind to.
# For testing purposes, toss a socket into /tmp instead.
sockpath = "/tmp/certmgr" if os.getuid() else "/var/run/certmgr"

if "reload" in sys.argv:
	# Rather than starting the server (asynchronously), connect to the server and tell it
	# to reload its certs.
	sock = socket.socket(socket.AF_UNIX)
	sock.connect(sockpath)
	sock.recv(1024) # Wait for the hello message
	sock.send(b"reload\n")
	sock.shutdown(socket.SHUT_RDWR)
	sys.exit()

async def main():
	with open("2fa.key") as f: # FileNotFoundError? Store the secret so the TOTPs work
		secret = f.read().strip()
		global totp
		totp = pyotp.TOTP(secret, 8)
	srv = await asyncio.start_unix_server(client, sockpath)
	if os.getuid() == 0:
		# Grant group permission on the socket so that non-root users can connect
		# TODO: Use the fd from the server instead?
		import grp
		os.chown(sockpath, 0, grp.getgrnam("adm").gr_gid)
		os.chmod(sockpath, 0o660)
	# _ = asyncio.create_task(poker()) # Hack: Push out "fresh" certs periodically
	try:
		await asyncio.Future()
	except asyncio.CancelledError:
		print("Shutting down.") # I don't hate you!

asyncio.run(main())
