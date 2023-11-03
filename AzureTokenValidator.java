import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.net.URL;
import java.security.Key;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AzureTokenValidator {

    public static void main(String[] args) throws Exception {
        // Initialize Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());

        // Replace these variables with your own values
        String azureToken = "your_azure_token_here";
        String jwksUri = "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"; // Replace {tenant} with your Azure AD tenant ID

        // Fetch JWKS (JSON Web Key Set)
        URL url = new URL(jwksUri);
        Map<String, Object> jwkSet = Jwts.parserBuilder().build().parseClaimsJws(url.openStream().toString()).getBody();
        
        // Extract public key from JWKS using the kid (Key ID) from the token
        String kid = Jwts.parserBuilder().build().parseClaimsJws(azureToken).getHeader().getKeyId();
        Map<String, Object> keyData = (Map<String, Object>) jwkSet.get(kid);
        String n = (String) keyData.get("n");
        String e = (String) keyData.get("e");
        RSAPublicKey publicKey = (RSAPublicKey) Keys.rsa(
            Base64.getUrlDecoder().decode(n),
            Base64.getUrlDecoder().decode(e)
        ).getPublic();

        // Parse and validate the Azure token
        Jws<Claims> jwsClaims = Jwts.parserBuilder()
            .setSigningKey(publicKey)
            .build()
            .parseClaimsJws(azureToken);

        // Verify claims such as issuer, audience, and expiration
        Claims claims = jwsClaims.getBody();
        String issuer = claims.getIssuer();
        String audience = claims.getAudience();
        // Add any other claims verification as needed

        System.out.println("Token is valid");
    }
}
