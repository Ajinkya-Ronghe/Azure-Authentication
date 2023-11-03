import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.net.URL;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

public class AzureTokenValidator {

    public static void main(String[] args) throws Exception {
        // Initialize Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());

        // Replace these variables with your own values
        String azureToken = "your_azure_token_here";
        String jwksUri = "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"; // Replace {tenant} with your Azure AD tenant ID

        // Fetch JWKS (JSON Web Key Set)
        JWKSet jwkSet = JWKSet.load(new URL(jwksUri));

        // Parse the token
        SignedJWT signedJWT = SignedJWT.parse(azureToken);

        // Get the public key for the token's key ID (kid)
        RSAKey rsaKey = (RSAKey) jwkSet.getKeyByKeyID(signedJWT.getHeader().getKeyID());

        // Verify the token's signature
        if (rsaKey != null) {
            RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
            if (signedJWT.verify(new RSASSAVerifier(publicKey))) {
                // Signature is valid, now check claims
                JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
                String issuer = claims.getIssuer();
                String audience = claims.getAudience().get(0);
                Date expirationTime = claims.getExpirationTime();
                Date now = new Date();

                if (issuer.equals("https://sts.windows.net/{tenant}/") &&
                        audience.equals("your_audience_here") &&
                        expirationTime != null &&
                        expirationTime.after(now)) {
                    // Token is valid
                    System.out.println("Token is valid");
                } else {
                    System.out.println("Token claims are invalid");
                }
            } else {
                System.out.println("Token signature is not valid");
            }
        } else {
            System.out.println("Token key ID (kid) not found in JWKS");
        }
    }
}
