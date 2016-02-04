package ch.eitchnet.pki;

public class PkiUtilMain {

	public static void main(String[] args) throws Exception {
		if (args.length != 1) {

			System.out.println("Usage: PkiUtil (csr | export)");
			System.exit(1);

		} else if (args[0].equals("csr")) {

			System.out.println("Certificate Signing Request");
			System.out.println("===========================");
			System.out.println();

			PkiUtil pki = new PkiUtil();

			pki.readSubjectFromStdin();
			pki.initKeyPair();
			pki.createCsr();
			pki.writePrivateKey();
			pki.writeCsr();

		} else if (args[0].equals("export")) {

			System.out.println("Export");
			System.out.println("===========================");
			System.out.println();

			PkiUtil pki = new PkiUtil();
			pki.readPrivateKeyFileNameFromStdin();
			pki.readCertificateFileNameFromStdin();
			pki.readSubjectFromCertificate();
			pki.writePkcs12();
			pki.writeJks();

		} else {
			System.out.println("Usage: PkiUtil (csr | export)");
			System.exit(1);
		}
	}
}
