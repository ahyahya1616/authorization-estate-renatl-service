package ma.fstt.authservice.utils;

import ma.fstt.authservice.exception.InvalidSignatureException;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;

/**
 * Utilitaires de vérification de signature Ethereum
 */
public class Web3SignatureUtils {

    private static final String ETHEREUM_MESSAGE_PREFIX = "\u0019Ethereum Signed Message:\n";

    /**
     * Récupère l'adresse Ethereum depuis une signature ECDSA
     */
    public static String ecRecover(String message, String signature) {
        try {

            String prefixedMessage = "\u0019Ethereum Signed Message:\n" + message.length() + message;
            byte[] messageHash = org.web3j.crypto.Hash.sha3(prefixedMessage.getBytes(StandardCharsets.UTF_8));

            // Extrairer, s, v depuis la signature
            byte[] signatureBytes = Numeric.hexStringToByteArray(signature);

            if (signatureBytes.length != 65) {
                throw new InvalidSignatureException("Signature invalide : longueur incorrecte");
            }

            byte v = signatureBytes[64];
            if (v < 27) {
                v += 27;
            }

            byte[] r = new byte[32];
            byte[] s = new byte[32];
            System.arraycopy(signatureBytes, 0, r, 0, 32);
            System.arraycopy(signatureBytes, 32, s, 0, 32);

            // Créer l'objet SignatureData
            Sign.SignatureData signatureData = new Sign.SignatureData(
                    v,
                    r,
                    s
            );

            // Récupérer la clé publique
            BigInteger publicKey = Sign.signedMessageHashToKey(messageHash, signatureData);

            // Convertir en adresse Ethereum
            String address = "0x" + Keys.getAddress(publicKey);

            return address;

        } catch (SignatureException e) {
            throw new InvalidSignatureException("Erreur lors de la récupération de l'adresse : " + e.getMessage());
        }
    }

    /**
     * Vérifie si une adresse Ethereum est valide
     */
    public static boolean isValidAddress(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }
        return address.matches("^0x[0-9a-fA-F]{40}$");
    }
}