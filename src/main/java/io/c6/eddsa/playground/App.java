package io.c6.eddsa.playground;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.ec.ed.EdDSAOperations;
import sun.security.ec.ed.EdDSAParameters;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Scanner;
import java.util.Set;

/**
 * Application root
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
			final var ed25519PvtKey = getResourceAsString("id_ed25519");
			LOGGER.info("ED25519 Private Key: \n{}", ed25519PvtKey);
			final PublicKey ed25519PubKey = getEdDSAPublicKeyFromPrivateKey(
					NamedParameterSpec.ED25519, ed25519PvtKey.getBytes(StandardCharsets.UTF_8));
			LOGGER.info("ED25519 Public Key: \n{}", ed25519PubKey);
		} catch (final NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
			LOGGER.error(e.getMessage(), e);
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
	 * @throws NoSuchAlgorithmException           invalid algorithm exception
	 * @throws InvalidKeySpecException            invalid key spec exception
	 * @throws InvalidAlgorithmParameterException invalid algorithm parameter exception
	 */
	@SuppressWarnings("SameParameterValue")
	public static PublicKey getEdDSAPublicKeyFromPrivateKey(final NamedParameterSpec spec, final byte[] pvtKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		if (!Set.of(NamedParameterSpec.ED25519, NamedParameterSpec.ED448).contains(spec)) {
			throw new InvalidAlgorithmParameterException("Allowed NamedParameterSpec are ED25519 and ED448");
		}
		final var edDSAOperations = new EdDSAOperations(EdDSAParameters.get(InvalidAlgorithmParameterException::new, spec));
		final var edECPoint = edDSAOperations.computePublic(pvtKey);
		final var edECPublicKeySpec = new EdECPublicKeySpec(spec, edECPoint);
		final var keyFactory = KeyFactory.getInstance(spec.getName());
		return keyFactory.generatePublic(edECPublicKeySpec);
	}
}
