package io.c6.eddsa.playground;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.ec.ed.EdDSAOperations;
import sun.security.ec.ed.EdDSAParameters;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Application root
 *
 * @author Chandrasekhar Thotakura
 */
public class App {

	private static final Logger LOGGER = LoggerFactory.getLogger(App.class);

	/**
	 * Main method
	 *
	 * @param args arguments
	 */
	public static void main(final String... args) {
		extractPublicKeyFromPrivateKey();
	}

	/**
	 * Extract public key from private key
	 */
	public static void extractPublicKeyFromPrivateKey() {
		try {
			var ed25519PvtKey = getResourceAsString("private.pem").trim();
			LOGGER.info("ED25519 Private Key: \n{}", ed25519PvtKey);
			ed25519PvtKey = trimPvtKey(ed25519PvtKey);
			LOGGER.info("ED25519 Private Key: {}", ed25519PvtKey);

//			var ed25519PvtKeyBytes = java.util.Base64.getDecoder().decode(ed25519PvtKey);
			var ed25519PvtKeyBytes = Base64.decodeBase64(ed25519PvtKey);
			LOGGER.info("ED25519 Private Key Bytes Length: {}\n{}", ed25519PvtKeyBytes.length, new String(ed25519PvtKeyBytes));
			ed25519PvtKeyBytes = Arrays.copyOfRange(ed25519PvtKeyBytes, 16, ed25519PvtKeyBytes.length);
			LOGGER.info("ED25519 Private Key Bytes Length: {}\n{}", ed25519PvtKeyBytes.length, new String(ed25519PvtKeyBytes));
//			ed25519PvtKeyBytes = "277952d828c229d3186dff659c37c9d0ba05d78317873bee7e286d493da0889f".getBytes(StandardCharsets.UTF_8);
//			LOGGER.info("ED25519 Private Key Bytes Length: {}\n{}", ed25519PvtKeyBytes.length, new String(ed25519PvtKeyBytes));
//			ed25519PvtKeyBytes = Base64.encodeBase64(ed25519PvtKeyBytes);
//			LOGGER.info("ED25519 Private Key Bytes Length: {}\n{}", ed25519PvtKeyBytes.length, new String(ed25519PvtKeyBytes));
//			ed25519PvtKeyBytes = Base64.decodeBase64(ed25519PvtKeyBytes);
//			LOGGER.info("ED25519 Private Key Bytes Length: {}\n{}", ed25519PvtKeyBytes.length, new String(ed25519PvtKeyBytes));
//			ed25519PvtKeyBytes = Hex.decodeHex(new String(ed25519PvtKeyBytes, StandardCharsets.UTF_8));
//			LOGGER.info("ED25519 Private Key Bytes Length: {}\n{}", ed25519PvtKeyBytes.length, new String(ed25519PvtKeyBytes));

			final var edECPrivateKey = getEdECPrivateKey(ed25519PvtKeyBytes);
			LOGGER.info("ED25519 Private Key: {}", edECPrivateKey);
			LOGGER.info("ED25519 Private Key Algo: {}", edECPrivateKey.getAlgorithm());
			ed25519PvtKeyBytes = edECPrivateKey.getBytes().orElse(new byte[0]);

			final PublicKey ed25519PubKey1 = getEdDSAPublicKeyFromPrivateKey(NamedParameterSpec.ED25519, ed25519PvtKeyBytes);
			final PublicKey ed25519PubKey2 = getEdDSAPublicKeyFromPrivateKey2(NamedParameterSpec.ED25519, ed25519PvtKeyBytes);
			LOGGER.info("ED25519 Public Key1: \n{}", ed25519PubKey1.toString().trim());
			LOGGER.info("ED25519 Public Key2: \n{}", ed25519PubKey2.toString().trim());

			String strPubKey1 = Base64.encodeBase64String(ed25519PubKey1.getEncoded());
			String strPubKey2 = Base64.encodeBase64String(ed25519PubKey2.getEncoded());
			LOGGER.info("ED25519 String Public Key1: {}", strPubKey1);
			LOGGER.info("ED25519 String Public Key2: {}", strPubKey2);
		} catch (final Exception e) {
			final var msg = Optional.ofNullable(e.getMessage()).orElse(">>>");
			LOGGER.error(msg, e);
		}
	}

	/**
	 * Get file content as string from resources directory
	 *
	 * @param filename filename
	 * @return file content
	 */
	@SuppressWarnings("SameParameterValue")
	public static String getResourceAsString(final String filename) {
		final var inputStream = App.class.getClassLoader().getResourceAsStream(filename);
		if (inputStream == null) {
			throw new IllegalArgumentException("Please create the ED25519 private key. Refer to the README.");
		}
		final var scanner = new Scanner(inputStream, StandardCharsets.UTF_8);
		final var resource = scanner.useDelimiter("\\A").next();
		scanner.close();
		return resource;
	}

	/**
	 * Inspired from <a href="https://stackoverflow.com/a/72602868">Stackoverflow.com solution</a>
	 *
	 * @param spec   either <code>NamedParameterSpec.ED25519</code> or <code>NamedParameterSpec.ED448</code>
	 * @param pvtKey private key binary
	 * @return instance of public key derived from the given private key binary
	 * @throws NoSuchAlgorithmException      invalid algorithm exception
	 * @throws InvalidKeySpecException       invalid key spec exception
	 * @throws InvalidParameterSpecException invalid parameter spec exception
	 */
	@SuppressWarnings("SameParameterValue")
	public static EdECPublicKey getEdDSAPublicKeyFromPrivateKey(final NamedParameterSpec spec, final byte[] pvtKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
		if (!Set.of(NamedParameterSpec.ED25519, NamedParameterSpec.ED448).contains(spec)) {
			throw new InvalidParameterSpecException("Allowed NamedParameterSpec are ED25519 and ED448");
		}
		final var edDSAOperations = new EdDSAOperations(EdDSAParameters.get(InvalidParameterSpecException::new, spec));
		final var edECPoint = edDSAOperations.computePublic(pvtKey);
		final var edECPublicKeySpec = new EdECPublicKeySpec(spec, edECPoint);
		final var keyFactory = KeyFactory.getInstance(spec.getName());
		return (EdECPublicKey) keyFactory.generatePublic(edECPublicKeySpec);
	}

	/**
	 * Inspired from <a href="https://stackoverflow.com/a/66442530">Stackoverflow.com solution</a>
	 *
	 * @param spec   either <code>NamedParameterSpec.ED25519</code> or <code>NamedParameterSpec.ED448</code>
	 * @param pvtKey private key binary
	 * @return instance of public key derived from the given private key binary
	 * @throws NoSuchAlgorithmException      invalid algorithm exception
	 * @throws InvalidKeySpecException       invalid key spec exception
	 * @throws InvalidParameterSpecException invalid parameter spec exception
	 */
	public static EdECPublicKey getEdDSAPublicKeyFromPrivateKey2(final NamedParameterSpec spec, final byte[] pvtKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
		if (!Set.of(NamedParameterSpec.ED25519, NamedParameterSpec.ED448).contains(spec)) {
			throw new InvalidParameterSpecException("Allowed NamedParameterSpec are ED25519 and ED448");
		}
		final var edECPoint = computeEdECPoint(pvtKey);
		final var edECPublicKeySpec = new EdECPublicKeySpec(spec, edECPoint);
		final var keyFactory = KeyFactory.getInstance(spec.getName());
		return (EdECPublicKey) keyFactory.generatePublic(edECPublicKeySpec);
	}

	public static EdECPoint computeEdECPoint(final byte[] pvtKey) {
		final var pvtKeyCopy = Arrays.copyOf(pvtKey, pvtKey.length);
		// determine if x was odd.
		final var xOdd = (pvtKeyCopy[pvtKeyCopy.length - 1] & 255) >> 7 == 1;
		// make sure most significant bit will be 0 - after reversing.
		pvtKeyCopy[pvtKeyCopy.length - 1] &= 127;
		// apparently we must reverse the byte array...
		reverse(pvtKeyCopy);
		final var y = new BigInteger(1, pvtKeyCopy);
		return new EdECPoint(xOdd, y);
	}

	public static void reverse(final byte[] array) {
		if (array == null) {
			return;
		}
		int i = 0;
		int j = array.length - 1;
		byte tmp;
		while (j > i) {
			tmp = array[j];
			array[j] = array[i];
			array[i] = tmp;
			j--;
			i++;
		}
	}

	public static String trimPvtKey(final String pvtKeyStr) {
		return Arrays.stream(pvtKeyStr.split(System.lineSeparator()))
				.filter(l -> !l.startsWith("-----")).collect(Collectors.joining());
	}

	public static EdECPrivateKey getEdECPrivateKey(final byte[] pvtKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		final var edECPrivateKeySpec = new EdECPrivateKeySpec(NamedParameterSpec.ED25519, pvtKey);
		final var keyFactory = KeyFactory.getInstance(NamedParameterSpec.ED25519.getName());
		return (EdECPrivateKey) keyFactory.generatePrivate(edECPrivateKeySpec);
	}
}
