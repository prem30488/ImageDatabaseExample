
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;


public class DataDecryptor {

	private static final int PUBLIC_KEY_SIZE = 294;
	private static final int EID_SIZE = 32;
	private static final int SECRET_KEY_SIZE = 256;
	private static final String TRANSFORMATION = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
	private static final String SECURITY_PROVIDER = "BC";
	private static final String DIGEST_ALGORITHM = "SHA-256";
	private static final String MASKING_FUNCTION = "MGF1";
	private static final int VECTOR_SIZE = 16;
	private static final int HMAC_SIZE = 32;
	private static final int BLOCK_SIZE = 128;
	private static final byte[] HEADER_DATA = "VERSION_1.0".getBytes();
	private static final String SIGNATURE_TAG = "Signature";
	private static final String MEC_TYPE = "DOM";

	private KeyStore.PrivateKeyEntry privateKey;
	private String publicKeyFile;
	private static Log log = LogFactory.getLog(DataDecryptor.class);

	/*
	 * static{ Security.addProvider(new BouncyCastleProvider()); }
	 */

	/**
	 * Constructor
	 * 
	 * @param keyStoreFile
	 *            - Location of .p12 file
	 * @param keyStorePassword
	 *            - Password of .p12 file
	 * @param alias
	 *            - Alias of the certificate in .p12 file
	 */
	public DataDecryptor(String keyStoreFile, char[] keyStorePassword, String publicKeyFile) {
		this.privateKey = getKeyFromFile(keyStoreFile, keyStorePassword);
		this.publicKeyFile = publicKeyFile;

		if (privateKey == null) {
			throw new RuntimeException("Key could not be read for digital signature. Please check value of signature "
					+ "alias and signature password, and restart the Auth Client");
		}
	}

	public byte[] decrypt(byte[] data) throws Exception {
		if (data == null || data.length == 0)
			throw new Exception("byte array data can not be null or blank array.");

		ByteArraySpliter arrSpliter = new ByteArraySpliter(data);

		byte[] secretKey = decryptSecretKeyData(arrSpliter.getEncryptedSecretKey(), arrSpliter.getIv(), privateKey.getPrivateKey());
		 System.out.println("secretKey:" +secretKey);
		byte[] plainData = decryptData(arrSpliter.getEncryptedData(), arrSpliter.getIv(), secretKey);

	
		 System.out.println("PlainData" +plainData);
		boolean result = validateHash(plainData);
		if (!result)
			throw new Exception("Integrity Validation Failed : "
			+ "The original data at client side and the decrypted data at server side is not identical");

		return trimHMAC(plainData);
	}

	/**
	 * To convert xml string with digital signature
	 * 
	 * @param document
	 *            : Document
	 * @return xmlString: String
	 * @throws PlatformException
	 */
	private static String covertDocumentToString(Document document) throws Exception {
		java.io.StringWriter sw = new java.io.StringWriter();
		try {
			DOMSource domSource = new DOMSource(document);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();

			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			// transformer.setOutputProperty(OutputKeys.ENCODING,"ISO-8859-1");
			// transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
			// transformer.setOutputProperty(OutputKeys.INDENT, "yes");

			StreamResult sr = new StreamResult(sw);
			transformer.transform(domSource, sr);
		} catch (TransformerException e) {
			e.printStackTrace();
		}

		return sw.toString();
	}

	private static void printUsage() {
		System.out.println("Please provide command-line arguments.");
		System.out.println("Syntax: java DecryptDataAndVerifySignature <ENC_FILE_PATH> <KEY_STORE_FILE_PATH> <KEY_STORE_PWD> <CERTIFICATE_FILE>");
		System.out.println("For Eg: java DecryptDataAndVerifySignature enc.xml keyStore.p12 test@123 certificate.cer");
	}

	public static byte[] getDataFromFile(String fileName) throws Exception {

		FileInputStream inputStream = new FileInputStream(fileName);
		byte[] encBytes = new byte[inputStream.available()];
		inputStream.read(encBytes, 0, encBytes.length);
		inputStream.close();
		return encBytes;
	}

	public static void writeToFile(byte[] plainData, String fileName) throws Exception {

		FileOutputStream os = new FileOutputStream(fileName);
		os.write(plainData, 0, plainData.length);
		os.flush();
		os.close();
	}

	private Document getDomObject(String string) throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder builder = dbf.newDocumentBuilder();
		InputSource is = new InputSource(new StringReader(string));
		is.setEncoding("UTF-8");
		return builder.parse(is);
	}

	private String getOutputFilename(String encryptedFile) {

		return encryptedFile + ".xml";
	}

	private PublicKey getPublicKey(String certFile) throws Exception {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		FileInputStream fis = new FileInputStream(certFile);
		Certificate cert = factory.generateCertificate(fis);
		// fis.close();
		return cert.getPublicKey();
	}

	private KeyStore.PrivateKeyEntry getKeyFromFile(String keyStoreFile, char[] keyStorePassword) {

		try {
			// Load the KeyStore and get the signing key and certificate.
			KeyStore ks = KeyStore.getInstance("PKCS12");
			FileInputStream keyFileStream = new FileInputStream(keyStoreFile);
			ks.load(keyFileStream, keyStorePassword);
			String alias = ks.aliases().nextElement();

			KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(keyStorePassword));

			if (entry == null)
				throw new Exception("Key not found for the given alias.");

			keyFileStream.close();

			return entry;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private byte[] decryptSecretKeyData(byte[] encryptedSecretKey, byte[] iv, PrivateKey privateKey) throws Exception {

		try {
			Cipher rsaCipher = Cipher.getInstance(TRANSFORMATION, SECURITY_PROVIDER);

			PSource pSrc = (new PSource.PSpecified(iv));

			rsaCipher
					.init(Cipher.DECRYPT_MODE, privateKey, new OAEPParameterSpec(DIGEST_ALGORITHM, MASKING_FUNCTION, MGF1ParameterSpec.SHA256, pSrc));

			return rsaCipher.doFinal(encryptedSecretKey);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			throw new Exception("Failed to decrypt AES secret key using RSA.", e);
		}
	}

	private byte[] decryptData(byte[] encryptedData, byte[] eid, byte[] secretKey) throws Exception {
		try {
			byte[][] iv = split(eid, VECTOR_SIZE);

			BufferedBlockCipher cipher = new BufferedBlockCipher(new CFBBlockCipher(new AESEngine(), BLOCK_SIZE));
			KeyParameter key = new KeyParameter(secretKey);

			cipher.init(false, new ParametersWithIV(key, iv[0]));

			int outputSize = cipher.getOutputSize(encryptedData.length);

			byte[] result = new byte[outputSize];
			int processLen = cipher.processBytes(encryptedData, 0, encryptedData.length, result, 0);
			cipher.doFinal(result, processLen);
			return result;
		} catch (InvalidCipherTextException txtExp) {
			throw new Exception("Decrypting data using AES failed", txtExp);
		}
	}

	private boolean validateHash(byte[] decryptedText) throws Exception {
		byte[][] hs = split(decryptedText, HMAC_SIZE);
		try {
			byte[] actualHash = generateHash(hs[1]);
		   /*log.info("as per decrypted????????--"+ new String(hs[0], "UTF-8"));
			  log.info("as per actual???????--"+new String(actualHash, "UTF-8"));*/
			  
			  System.out.println("as per decrypted????????--"+ new String(hs[0], "UTF-8"));
			  System.out.println("as per actual???????--"+new String(actualHash, "UTF-8"));
			if (new String(hs[0], "UTF-8").equals(new String(actualHash, "UTF-8"))) {
				return true;
			} else {
				return false;
			}
		} catch (Exception he) {
			throw new Exception("Not able to compute hash.", he);
		}
	}

	private byte[] trimHMAC(byte[] decryptedText) {
		byte[] actualText;
		if (decryptedText == null || decryptedText.length <= HMAC_SIZE) {
			actualText = new byte[0];
		} else {
			actualText = new byte[decryptedText.length - HMAC_SIZE];
			System.arraycopy(decryptedText, HMAC_SIZE, actualText, 0, actualText.length);
		}
		return actualText;
	}

	private static class ByteArraySpliter {

		private final byte[] headerVersion;
		private final byte[] iv;
		private final byte[] encryptedSecretKey;
		private final byte[] encryptedData;
		private final byte[] publicKeyData;

		public ByteArraySpliter(byte[] data) throws Exception {
			int offset = 0;
			headerVersion = new byte[HEADER_DATA.length];
			copyByteArray(data, 0, headerVersion.length, headerVersion);
			offset = offset + HEADER_DATA.length;
			publicKeyData = new byte[PUBLIC_KEY_SIZE];
			copyByteArray(data, offset, publicKeyData.length, publicKeyData);
			offset = offset + PUBLIC_KEY_SIZE;
			iv = new byte[EID_SIZE];
			copyByteArray(data, offset, iv.length, iv);
			offset = offset + EID_SIZE;
			encryptedSecretKey = new byte[SECRET_KEY_SIZE];
			copyByteArray(data, offset, encryptedSecretKey.length, encryptedSecretKey);
			offset = offset + SECRET_KEY_SIZE;
			encryptedData = new byte[data.length - offset];
			copyByteArray(data, offset, encryptedData.length, encryptedData);
		}

		public byte[] getIv() {
			return iv;
		}

		public byte[] getEncryptedSecretKey() {
			return encryptedSecretKey;
		}

		public byte[] getEncryptedData() {
			return encryptedData;
		}

		private void copyByteArray(byte[] src, int offset, int length, byte[] dest) throws Exception {
			try {
				System.arraycopy(src, offset, dest, 0, length);
			} catch (Exception e) {

				throw new Exception("Decryption failed, Corrupted packet ", e);
			}
		}
	}

	private byte[][] split(byte[] src, int n) {
		byte[] l, r;
		if (src == null || src.length <= n) {
			l = src;
			r = new byte[0];
		} else {
			l = new byte[n];
			r = new byte[src.length - n];
			System.arraycopy(src, 0, l, 0, n);
			System.arraycopy(src, n, r, 0, r.length);
		}
		return new byte[][] { l, r };
	}

	public byte[] generateHash(byte[] message) throws Exception {
		byte[] hash = null;
		try {
			// Registering the Bouncy Castle as the RSA provider.
			MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM, SECURITY_PROVIDER);
			digest.reset();
			hash = digest.digest(message);
		} catch (GeneralSecurityException e) {
			throw new Exception("SHA-256 Hashing algorithm not available");
		}
		return hash;
	}

	public boolean verify(String xml) throws Exception {
		try {
			Document xmlDoc = getDomObject(xml);
			/* StringBuilder strBuilder=new StringBuilder(); */
			PublicKey publicKey = getPublicKey(publicKeyFile);
			log.info("publicKey in Datadecryptor calss=="+publicKey);
			NodeList nl = xmlDoc.getElementsByTagNameNS(XMLSignature.XMLNS, SIGNATURE_TAG);
			if (nl.getLength() == 0)
				throw new IllegalArgumentException("Cannot find Signature element");

			XMLSignatureFactory fac = XMLSignatureFactory.getInstance(MEC_TYPE);
			DOMValidateContext valContext = new DOMValidateContext(publicKey, nl.item(0));
			// enable reference caching in your validation context
			/*
			 * valContext.setProperty ("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
			 */

			XMLSignature signature = fac.unmarshalXMLSignature(valContext);
			boolean verificationResult = signature.validate(valContext);
			/*
			 * if(!verificationResult) { boolean sv = signature.getSignatureValue().validate(valContext);
			 * System.out.println("signature validation status in method1: " + sv); Iterator i =
			 * signature.getSignedInfo().getReferences().iterator(); for (int j=0; i.hasNext(); j++) {
			 * System.out.println("Pre-digested Input:"); InputStreamReader isr = new InputStreamReader((((Reference)
			 * i.next()).getDigestInputStream()),"UTF-8"); char[] cbuf = new char[1024]; while (isr.read(cbuf, 0, 1024)
			 * != -1) { System.out.print(cbuf); strBuilder.append(cbuf); }
			 * System.out.println("finally lets see whats digest\n"+strBuilder.toString());
			 * 
			 * boolean refValid = ((Reference) i.next()).validate(valContext);
			 * System.out.println("ref["+j+"] validity status in method1: " + refValid); }
			 * 
			 * }
			 */
			return verificationResult;
		} catch (MarshalException mExp) {
			throw new Exception(mExp);
		} catch (XMLSignatureException xmlExp) {
			throw new Exception(xmlExp);
		}
	}

	private static Node getSignatureNode(Document inputDocument) {
		if (inputDocument != null) {
			Element rootElement = inputDocument.getDocumentElement();
			if (rootElement != null) {
				NodeList nl = rootElement.getChildNodes();
				if (nl != null) {
					for (int i = 0; i < nl.getLength(); i++) {
						Node n = nl.item(i);
						if (n != null) {
							if (n.getNodeName() != null && "signature".equalsIgnoreCase(n.getLocalName())) {
								return n;
							}
						}
					}
				}
			}
		}

		return null;
	}

	public static Document removeSignature(Document inputDocument) {

		if (inputDocument != null) {
			Element rootElement = inputDocument.getDocumentElement();
			Node n = getSignatureNode(inputDocument);
			if (n != null) {
				rootElement.removeChild(n);
			}
		}

		return inputDocument;
	}
}
