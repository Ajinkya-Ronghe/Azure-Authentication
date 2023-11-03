import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

public class AzureTokenValidator {

    public static void main(String[] args) throws Exception {
        // Replace these variables with your own values
        String azureToken = "your_azure_token_here";
        String jwksUri = "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"; // Replace {tenant} with your Azure AD tenant ID

        // Fetch JWKS (JSON Web Key Set)
        URL url = new URL(jwksUri);
        Map<String, Object> jwkSet = Jwts.parserBuilder().build().parseClaimsJws(url.openStream().toString()).getBody();

        // Extract the public key from JWKS using the kid (Key ID) from the token
        String kid = Jwts.parserBuilder().build().parseClaimsJws(azureToken).getHeader().getKeyId();
        Map<String, Object> keyData = (Map<String, Object>) jwkSet.get(kid);
        String n = (String) keyData.get("n");
        String e = (String) keyData.get("e");
        
        byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(e);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(modulusBytes));

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
