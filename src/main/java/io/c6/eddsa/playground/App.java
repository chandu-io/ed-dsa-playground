package io.c6.eddsa.playground;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.ec.ed.EdDSAOperations;
import sun.security.ec.ed.EdDSAParameters;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Application root
 *
 * @author Chandrasekhar Thotakura
 */
@SuppressWarnings("unused")
public class App {

	private static final Logger LOGGER = LoggerFactory.getLogger(App.class);

	/**
	 * Main method
	 *
	 * @param args arguments
	 */
	public static void main(final String... args) {
		deriveEdECPublicKeyFromEdECPrivateKey();
	}

	/**
	 * Extract public key from private key
	 */
	public static void deriveEdECPublicKeyFromEdECPrivateKey() {
		try {
			final var encodedEd25519PvtKey = extractPEMKeyContent(getResourceAsString("private.pem"));
			LOGGER.info("Encoded ED25519 Private Key: {}", encodedEd25519PvtKey);
			final var encodedEd25519PublicKey = extractPEMKeyContent(getResourceAsString("public.pem"));
			LOGGER.info("Encoded ED25519 Private Key: {}", encodedEd25519PublicKey);

			final var ed25519PvtKeyBytes = Base64.getDecoder().decode(encodedEd25519PvtKey);
			LOGGER.info("ED25519 Private Key Bytes and Length: ({}) => {}", new String(ed25519PvtKeyBytes), ed25519PvtKeyBytes.length);
			// trim first 16-bytes: https://xrpl.org/cryptographic-keys.html#ed25519-key-derivation
			// https://stackoverflow.com/questions/77274300/convert-existing-ed25519-private-key-file-in-openssl-private-format-into-ssh-s#:~:text=For%20Ed25519%2C%20the%20last%2032,here%2C%20section%20OpenSSH%20Private%20Keys.
			final var ed25519PvtKeyBytes2 = Arrays.copyOfRange(ed25519PvtKeyBytes, 16, ed25519PvtKeyBytes.length);
			LOGGER.info("ED25519 Private Key Bytes and Length: ({}) => {}", new String(ed25519PvtKeyBytes2), ed25519PvtKeyBytes2.length);

			final var edECPrivateKey = getEdECPrivateKey(ed25519PvtKeyBytes2);
			LOGGER.info("ED25519 Private Key: {}", edECPrivateKey);
			// derive from the pvt key instance
			final var ed25519PvtKeyBytes3 = edECPrivateKey.getBytes().orElseThrow();

			final var edECPublicKey = getEdECPublicKeyFromPrivateKey(NamedParameterSpec.ED25519, ed25519PvtKeyBytes3);
			//final var edECPublicKey = getEdECPublicKeyFromPrivateKey2(NamedParameterSpec.ED25519, ed25519PvtKeyBytes3);
			LOGGER.info("ED25519 Public Key: \n{}", edECPublicKey.toString().trim());
			final var derivedEncodedEd25519PublicKey = Base64.getEncoder().encodeToString(edECPublicKey.getEncoded());
			LOGGER.info("Derived encoded ED25519 Public Key: {}", derivedEncodedEd25519PublicKey);

			if (!encodedEd25519PublicKey.equals(derivedEncodedEd25519PublicKey)) {
				throw new RuntimeException("Derived EncodedEd25519PublicKey is invalid");
			}
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
	public static EdECPublicKey getEdECPublicKeyFromPrivateKey(final NamedParameterSpec spec, final byte[] pvtKey)
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
	public static EdECPublicKey getEdECPublicKeyFromPrivateKey2(final NamedParameterSpec spec, final byte[] pvtKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
		if (!Set.of(NamedParameterSpec.ED25519, NamedParameterSpec.ED448).contains(spec)) {
			throw new InvalidParameterSpecException("Allowed NamedParameterSpec are ED25519 and ED448");
		}
		final var edECPoint = computeEdECPoint(pvtKey);
		final var edECPublicKeySpec = new EdECPublicKeySpec(spec, edECPoint);
		final var keyFactory = KeyFactory.getInstance(spec.getName());
		return (EdECPublicKey) keyFactory.generatePublic(edECPublicKeySpec);
	}

	/**
	 * Compute <code>EdECPoint</code> from the given private key binary
	 *
	 * @param pvtKey private key binary
	 * @return EdECPoint
	 */
	public static EdECPoint computeEdECPoint(final byte[] pvtKey) {
		final var pvtKeyCopy = Arrays.copyOf(pvtKey, pvtKey.length);
		final var msb = pvtKeyCopy[pvtKeyCopy.length - 1];
		final var xOdd = (msb & 255) >> 7 == 1;
		pvtKeyCopy[pvtKeyCopy.length - 1] &= 127;
		reverse(pvtKeyCopy);
		final var y = new BigInteger(1, pvtKeyCopy);
		return new EdECPoint(xOdd, y);
	}

	/**
	 * Compute <code>EdECPoint</code> from the given private key binary
	 * <p>
	 * Inspired from <a href="https://github.com/openjdk/jdk/blob/jdk-17-ga/test/lib/jdk/test/lib/Convert.java#L64">openjdk tests</a>
	 *
	 * @param pvtKey private key binary
	 * @return EdECPoint
	 */
	private static EdECPoint computeEdECPoint2(final byte[] pvtKey) {
		final var pvtKeyCopy = Arrays.copyOf(pvtKey, pvtKey.length);
		final var msb = pvtKeyCopy[pvtKeyCopy.length - 1];
		final var xOdd = (msb & 0x80) != 0;
		pvtKeyCopy[pvtKeyCopy.length - 1] &= (byte) 0x7F;
		reverse(pvtKeyCopy);
		final var y = new BigInteger(1, pvtKeyCopy);
		return new EdECPoint(xOdd, y);
	}

	/**
	 * Reverse the byte array
	 *
	 * @param arr input array
	 */
	public static void reverse(final byte[] arr) {
		int i = 0;
		int j = arr.length - 1;
		while (i < j) {
			swap(arr, i, j);
			i++;
			j--;
		}
	}

	/**
	 * Swap element in the array from the positions given
	 *
	 * @param arr input array
	 * @param i   first position
	 * @param j   second position
	 */
	public static void swap(final byte[] arr, final int i, final int j) {
		byte tmp = arr[i];
		arr[i] = arr[j];
		arr[j] = tmp;
	}

	/**
	 * Extract the Base64 encoded content from PEM string
	 *
	 * @param pemKeyStrWithPrefixAndSuffix PEM key string with prefix and suffix
	 * @return PEM key string
	 */
	public static String extractPEMKeyContent(final String pemKeyStrWithPrefixAndSuffix) {
		return Arrays.stream(pemKeyStrWithPrefixAndSuffix.split(System.lineSeparator()))
				.filter(l -> !l.startsWith("-----")).collect(Collectors.joining());
	}

	/**
	 * Create an instance of <code>EdECPrivateKey</code> from the given private key binary
	 *
	 * @param pvtKey private key binary
	 * @return instance of <code>EdECPrivateKey</code>
	 * @throws NoSuchAlgorithmException algorithm exception
	 * @throws InvalidKeySpecException  key spec exception
	 */
	public static EdECPrivateKey getEdECPrivateKey(final byte[] pvtKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		final var edECPrivateKeySpec = new EdECPrivateKeySpec(NamedParameterSpec.ED25519, pvtKey);
		final var keyFactory = KeyFactory.getInstance(NamedParameterSpec.ED25519.getName());
		return (EdECPrivateKey) keyFactory.generatePrivate(edECPrivateKeySpec);
	}
}
