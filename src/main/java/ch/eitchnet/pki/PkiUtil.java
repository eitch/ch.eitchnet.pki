package ch.eitchnet.pki;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.function.Function;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class PkiUtil {

	static {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
	}

	public static final String SIGNATURE_ALGORITHM = "sha256withRSAEncryption";
	public static final String KEY_GENERATION_ALGORITHM = "RSA";
	public static final int ROOT_KEYSIZE = 4096;

	public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

	public static final List<String> COUNTRY_CODES = Collections.unmodifiableList(java.util.Arrays.asList(new String[] {
			"AF", "AX", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR", "AM", "AW", "AU", "AT", "AZ", "BS", "BH",
			"BD", "BB", "BY", "BE", "BZ", "BJ", "BM", "BT", "BO", "BQ", "BA", "BW", "BV", "BR", "IO", "BN", "BG", "BF",
			"BI", "KH", "CM", "CA", "CV", "KY", "CF", "TD", "CL", "CN", "CX", "CC", "CO", "KM", "CG", "CD", "CK", "CR",
			"CI", "HR", "CU", "CW", "CY", "CZ", "DK", "DJ", "DM", "DO", "EC", "EG", "SV", "GQ", "ER", "EE", "ET", "FK",
			"FO", "FJ", "FI", "FR", "GF", "PF", "TF", "GA", "GM", "GE", "DE", "GH", "GI", "GR", "GL", "GD", "GP", "GU",
			"GT", "GG", "GN", "GW", "GY", "HT", "HM", "VA", "HN", "HK", "HU", "IS", "IN", "ID", "IR", "IQ", "IE", "IM",
			"IL", "IT", "JM", "JP", "JE", "JO", "KZ", "KE", "KI", "KP", "KR", "KW", "KG", "LA", "LV", "LB", "LS", "LR",
			"LY", "LI", "LT", "LU", "MO", "MK", "MG", "MW", "MY", "MV", "ML", "MT", "MH", "MQ", "MR", "MU", "YT", "MX",
			"FM", "MD", "MC", "MN", "ME", "MS", "MA", "MZ", "MM", "NA", "NR", "NP", "NL", "NC", "NZ", "NI", "NE", "NG",
			"NU", "NF", "MP", "NO", "OM", "PK", "PW", "PS", "PA", "PG", "PY", "PE", "PH", "PN", "PL", "PT", "PR", "QA",
			"RE", "RO", "RU", "RW", "BL", "SH", "KN", "LC", "MF", "PM", "VC", "WS", "SM", "ST", "SA", "SN", "RS", "SC",
			"SL", "SG", "SX", "SK", "SI", "SB", "SO", "ZA", "GS", "SS", "ES", "LK", "SD", "SR", "SJ", "SZ", "SE", "CH",
			"SY", "TW", "TJ", "TZ", "TH", "TL", "TG", "TK", "TO", "TT", "TN", "TR", "TM", "TC", "TV", "UG", "UA", "AE",
			"GB", "US", "UM", "UY", "UZ", "VU", "VE", "VN", "VG", "VI", "WF", "EH", "YE", "ZM", "ZW" }));

	public static final String REGEX_DOMAIN = "(\\[((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\.){3}|((([a-zA-Z0-9\\-]+)\\.)+))([a-zA-Z]{2,}|(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\])";
	public static final String REGEX_EMAIL = "([a-zA-Z0-9_\\-])([a-zA-Z0-9_\\-\\.]*)@(\\[((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\.){3}|((([a-zA-Z0-9\\-]+)\\.)+))([a-zA-Z]{2,}|(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\])";
	public static final String REGEX_WORD = "[\u00C0-\u017Fa-zA-Z0-9'][\u00C0-\u017Fa-zA-Z0-9\\-' ]*";
	public static final String REGEX_YES_NO = "[yYnN]";

	public static final Pattern YES_NO_PATTERN = Pattern.compile(REGEX_YES_NO);
	public static final Pattern WORD_PATTERN = Pattern.compile(REGEX_WORD);
	public static final Pattern EMAIL_PATTERN = Pattern.compile(REGEX_EMAIL);
	public static final Pattern DOMAIN_PATTERN = Pattern.compile(REGEX_DOMAIN);

	private String country;
	private String stateOrProvince;
	private String localityCity;
	private String organisation;
	private String organisationalUnit;
	private String commonName;
	private String email;

	private String privateKeyFileName;

	private KeyPair keyPair;
	private PKCS10CertificationRequest csr;
	private X509Certificate certificate;

	public PkiUtil() {
		this.country = "CH";
		this.stateOrProvince = "Zürich";
		this.localityCity = "Zürich";
		this.organisation = "My Company";
		this.organisationalUnit = "Development";
		this.commonName = "www.mycompany.ch";
		this.email = "dev@mycompany.ch";
	}

	public String getCountry() {
		return this.country;
	}

	public String getStateOrProvince() {
		return this.stateOrProvince;
	}

	public String getLocalityCity() {
		return this.localityCity;
	}

	public String getOrganisation() {
		return this.organisation;
	}

	public String getOrganisationalUnit() {
		return this.organisationalUnit;
	}

	public String getCommonName() {
		return this.commonName;
	}

	public String getEmail() {
		return this.email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public boolean setSubject(String country, String stateOrProvince, String localityCity, String organisation,
			String organisationalUnit, String commonName, String email) {

		boolean ok = true;
		if (this.country == null) {
			System.out.println("Missing subject value C");
			ok = false;
		}
		if (this.stateOrProvince == null) {
			System.out.println("Missing subject value ST");
			ok = false;
		}
		if (this.localityCity == null) {
			System.out.println("Missing subject value L");
			ok = false;
		}
		if (this.organisation == null) {
			System.out.println("Missing subject value O");
			ok = false;
		}
		if (this.organisationalUnit == null) {
			System.out.println("Missing subject value OU");
			ok = false;
		}
		if (this.commonName == null) {
			System.out.println("Missing subject value CN");
			ok = false;
		}
		if (this.email == null) {
			System.out.println("Missing subject value EMAILADDRESS");
			ok = false;
		}

		if (!ok)
			return false;

		this.country = country;
		this.stateOrProvince = stateOrProvince;
		this.localityCity = localityCity;
		this.organisation = organisation;
		this.organisationalUnit = organisationalUnit;
		this.commonName = commonName;
		this.email = email;

		return true;
	}

	public PrivateKey getPrivateKey() {
		if (this.keyPair == null)
			throw new IllegalStateException("KeyPair not yet initialized!");

		return this.keyPair.getPrivate();
	}

	public PublicKey getPublicKey() {
		if (this.keyPair == null)
			throw new IllegalStateException("KeyPair not yet initialized!");

		return this.keyPair.getPublic();
	}

	public void initKeyPair() {
		System.out.println("Initializing KeyPair...");
		if (this.keyPair != null)
			throw new IllegalStateException("KeyPair already initialized!");

		try {
			// Create private/public key pair
			KeyPairGenerator gen = KeyPairGenerator.getInstance(KEY_GENERATION_ALGORITHM);
			gen.initialize(ROOT_KEYSIZE);
			this.keyPair = gen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Failed to generate a new key pair with size " + ROOT_KEYSIZE, e);
		}
	}

	public X500Principal getX500Principal() {
		StringBuilder sb = new StringBuilder();
		sb.append("C=");
		sb.append(this.country);
		sb.append(", ST=");
		sb.append(this.stateOrProvince);
		sb.append(", L=");
		sb.append(this.localityCity);
		sb.append(", O=");
		sb.append(this.organisation);
		sb.append(", OU=");
		sb.append(this.organisationalUnit);
		sb.append(", CN=");
		sb.append(this.commonName);
		sb.append(", EMAILADDRESS=");
		sb.append(this.email);
		return new X500Principal(sb.toString());
	}

	public void createCsr() {
		if (this.keyPair == null)
			throw new IllegalStateException("KeyPair not yet initialized!");
		if (this.csr != null)
			throw new IllegalStateException("CSR already created!");

		System.out.println("Creating Certificate Signing Request...");
		try {

			// Create subject
			X500Principal subject = getX500Principal();

			ContentSigner signGen = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(getPrivateKey());

			PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject,
					getPublicKey());
			this.csr = builder.build(signGen);

		} catch (OperatorCreationException e) {
			throw new RuntimeException("Failed to create CSR with SHA256 signature algorithm", e);
		}
	}

	public void writeCsr() {
		File csrFileName = new File(getCommonName() + ".csr");
		System.out.println("Writing CSR to " + csrFileName);
		writeObject(csr, csrFileName);
	}

	public void writePrivateKey() {
		File privateKeyFileName = new File(getCommonName() + ".key");
		System.out.println("Writing PrivateKey to " + privateKeyFileName);
		writeObject(getPrivateKey(), privateKeyFileName);
	}

	private void writeObject(Object obj, File file) {
		try (OutputStream out = new FileOutputStream(file);
				JcaPEMWriter pem = new JcaPEMWriter(new OutputStreamWriter(out));) {
			pem.writeObject(obj);
			pem.flush();
		} catch (IOException e) {
			throw new RuntimeException("Failed to write " + obj + " to " + file, e);
		}
	}

	public void writePkcs12() {
		if (this.certificate == null)
			throw new IllegalStateException("Certificate not yet initialized!");
		if (this.commonName == null || this.commonName.isEmpty())
			throw new IllegalStateException("commonName not defined!");

		File p12FileName = new File(getCommonName() + ".p12");
		System.out.println("Writing PKCS12 to " + p12FileName);

		try (OutputStream outputStream = new FileOutputStream(p12FileName)) {

			// initialize
			KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12");
			pkcs12KeyStore.load(null, null);

			// add certificate with private key
			Certificate[] certificateChain = { certificate };
			pkcs12KeyStore.setKeyEntry(this.commonName, getPrivateKey(), null, certificateChain);

			// write to file
			pkcs12KeyStore.store(outputStream, "changeit".toCharArray());
			outputStream.flush();

			System.out.println("Keystore password: changeit");

		} catch (Exception e) {
			throw new RuntimeException("Failed to write PKCS12 to " + p12FileName, e);
		}
	}

	public void writeJks() {
		if (this.certificate == null)
			throw new IllegalStateException("Certificate not yet initialized!");
		if (this.commonName == null || this.commonName.isEmpty())
			throw new IllegalStateException("commonName not defined!");

		File jksFileName = new File(getCommonName() + ".jks");
		System.out.println("Writing JKS to " + jksFileName);

		try (OutputStream outputStream = new FileOutputStream(jksFileName)) {

			// initialize
			KeyStore javaKeyStore = KeyStore.getInstance("JKS");
			javaKeyStore.load(null, null);

			// add certificate with private key
			Certificate[] certificateChain = { certificate };
			javaKeyStore.setKeyEntry(this.commonName, getPrivateKey(), "changeit".toCharArray(), certificateChain);

			// write to file
			javaKeyStore.store(outputStream, "changeit".toCharArray());
			outputStream.flush();

			System.out.println("Keystore password: changeit");

		} catch (Exception e) {
			throw new RuntimeException("Failed to write JKS to " + jksFileName, e);
		}
	}

	public void readSubjectFromStdin() {

		System.out.println(
				"Please enter the following fields as input\n" + "for the subject of the certificate signing request\n"
						+ "The values in brackets are default values: ");
		System.out.println();

		Function<String, Boolean> wordMatcher = value -> value.isEmpty() || WORD_PATTERN.matcher(value).matches();
		Function<String, Boolean> emailMatcher = email -> email.isEmpty() || EMAIL_PATTERN.matcher(email).matches();
		Function<String, Boolean> countryMatcher = country -> country.isEmpty() || COUNTRY_CODES.contains(country);
		Function<String, Boolean> domainMatcher = domain -> domain.isEmpty() || DOMAIN_PATTERN.matcher(domain).matches()
				|| WORD_PATTERN.matcher(domain).matches();

		String errorMsg = "Please don't use any special characters.";

		boolean nok = true;
		while (nok) {
			Scanner scanner = new Scanner(System.in);

			this.country = askForValue(this.country, scanner, "Country", "Not a legal country code!", countryMatcher);
			this.stateOrProvince = askForValue(this.stateOrProvince, scanner, "State/Province", errorMsg, wordMatcher);
			this.localityCity = askForValue(this.localityCity, scanner, "City", errorMsg, wordMatcher);
			this.organisation = askForValue(this.organisation, scanner, "Organisation", errorMsg, wordMatcher);
			this.organisationalUnit = askForValue(this.organisationalUnit, scanner, "Organisational Unit", errorMsg,
					wordMatcher);
			this.commonName = askForValue(this.commonName, scanner, "Common Name",
					"The common name must be a valid domain name, or be composed of only words.", domainMatcher);
			this.email = askForValue(this.email, scanner, "E-Mail", "The given e-mail is not valid.", emailMatcher);

			System.out.println();
			System.out.println("Do you want to use the following subject: ");
			System.out.println(getX500Principal().getName(X500Principal.RFC2253));
			System.out.println();

			String ok = askForValue("y", scanner, "y/n", null,
					value -> value.isEmpty() || YES_NO_PATTERN.matcher(value).matches());
			if (ok.toLowerCase().equals("y"))
				nok = false;
			else
				System.out.println("\nRepeating questions.");
		}
	}

	public boolean readSubjectFromCertificate() {
		System.out.println("Parsing Subject from Certificate...");

		// first reset subject
		String country = null;
		String stateOrProvince = null;
		String localityCity = null;
		String organisation = null;
		String organisationalUnit = null;
		String commonName = null;
		String email = null;

		X500Principal subject = this.certificate.getSubjectX500Principal();
		X500Name x500Name = new X500Name(subject.getName(X500Principal.RFC2253));

		RDN[] rdNs = x500Name.getRDNs();
		for (RDN rdn : rdNs) {
			AttributeTypeAndValue value = rdn.getFirst();
			if (value == null)
				continue;

			ASN1ObjectIdentifier type = value.getType();
			String v = value.getValue().toString();
			if (type.equals(BCStyle.C)) {
				country = v;
			} else if (type.equals(BCStyle.ST)) {
				stateOrProvince = v;
			} else if (type.equals(BCStyle.L)) {
				localityCity = v;
			} else if (type.equals(BCStyle.O)) {
				organisation = v;
			} else if (type.equals(BCStyle.OU)) {
				organisationalUnit = v;
			} else if (type.equals(BCStyle.CN)) {
				commonName = v;
			} else if (type.equals(BCStyle.EmailAddress)) {
				email = v;
			}
		}

		return setSubject(country, stateOrProvince, localityCity, organisation, organisationalUnit, commonName, email);
	}

	public void readPrivateKeyFileNameFromStdin() {
		boolean nok = true;
		while (nok) {
			Scanner scanner = new Scanner(System.in);

			// read the private key
			Function<String, Boolean> matcher = value -> !value.isEmpty() && new File(value).isFile();
			this.privateKeyFileName = "";
			this.privateKeyFileName = askForValue(this.privateKeyFileName, scanner, "Private key file name",
					"Value must not be empty and file must exist.", matcher);
			try {
				File privateKeyFile = new File(this.privateKeyFileName);
				try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile))) {
					Object object = pemParser.readObject();
					JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(PROVIDER_NAME);
					this.keyPair = converter.getKeyPair((PEMKeyPair) object);
				}

				System.out.println("Read private and public key " + this.privateKeyFileName + " using "
						+ getPrivateKey().getAlgorithm() + " in format " + getPrivateKey().getFormat());

				nok = false;

			} catch (Exception e) {
				System.out.println(
						"Failed to read private key " + this.privateKeyFileName + " due to error\n" + e.getMessage());
			}
		}
	}

	public void readCertificateFileNameFromStdin() {
		boolean nok = true;
		while (nok) {
			Scanner scanner = new Scanner(System.in);

			// read the private key
			Function<String, Boolean> matcher = value -> !value.isEmpty() && new File(value).isFile();
			String certificateFileName = "";
			certificateFileName = askForValue(certificateFileName, scanner, "Certificate file name",
					"Value must not be empty and file must exist.", matcher);
			try {

				try (FileInputStream fis = new FileInputStream(certificateFileName)) {
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					this.certificate = (X509Certificate) cf.generateCertificate(fis);
				}

				X500Principal issuer = certificate.getIssuerX500Principal();
				X500Principal subject = this.certificate.getSubjectX500Principal();

				System.out.println("Read certificate " + certificateFileName);
				System.out.println("Certificate is signed by " + issuer.getName(X500Principal.RFC2253));
				System.out.println("Certificate has subject " + subject.getName(X500Principal.RFC2253));

				System.out.println();
				System.out.println("Do you want to use this certificate? ");
				System.out.println();

				String ok = askForValue("y", scanner, "y/n", null,
						value -> value.isEmpty() || YES_NO_PATTERN.matcher(value).matches());
				if (ok.toLowerCase().equals("y"))
					nok = false;
				else
					System.out.println("\nRepeating questions.");

			} catch (Exception e) {
				System.out.println(
						"Failed to read certificate " + certificateFileName + " due to error\n" + e.getMessage());
			}
		}
	}

	private String askForValue(String defValue, Scanner scanner, String msg, String errorMsg,
			Function<String, Boolean> matcher) {
		System.out.print(msg + " [" + defValue + "] : ");
		String value = scanner.nextLine();
		while (!matcher.apply(value)) {
			if (errorMsg != null)
				System.out.println(errorMsg);
			System.out.print(msg + " [" + defValue + "] : ");
			value = scanner.nextLine();
		}

		return value.isEmpty() ? defValue : value;
	}
}
