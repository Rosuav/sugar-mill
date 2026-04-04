int main(int argc, array (string) argv) {
	if (argc < 3 || !(int)argv[2]) exit(3, "USAGE: pike %s certificate days\neg pike %<s db.rosuav.com.pem 30\nExits 0 if the certificate is valid for at least that many more days, 1 if it is not.\nIf certificate does not exist, exits 2.\n", argv[0]);
	string raw = Stdio.read_file(argv[1]);
	if (!raw) return 2; //File not found, or not readable.
	catch {
		object cert = Standards.X509.decode_certificate(Standards.PEM.Messages(raw)->get_certificates()[0]);
		int days_remaining = (cert->not_after - time()) / 86400; //Complete days of validity
		if ((int)argv[2] <= 0) exit(1, "Days remaining: %d\n", days_remaining);
		if (days_remaining >= (int)argv[2]) return 0;
		return 1;
	};
	return 2; //Any sort of parse error, just return 2 for simplicity.
}
