import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;

public class AzureTokenValidator {

    public static void main(String[] args) throws Exception {
        // Replace these variables with your own values
        String azureToken = "your_azure_token_here";
        String jwksUri = "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"; // Replace {tenant} with your Azure AD tenant ID

        // Decode the header of the JWT token to retrieve the 'kid'
        String headerEncoded = azureToken.split("\\.")[0];
        String headerJson = new String(Base64.getUrlDecoder().decode(headerEncoded));
        Map<String, Object> headerMap = new ObjectMapper().readValue(headerJson, Map.class);
        String tokenKid = (String) headerMap.get("kid");

        // Fetch JWKS (JSON Web Key Set)
        URL url = new URL(jwksUri);
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> jwkSetMap = mapper.readValue(url, Map.class);
        Map<String, Object> keyData = null;

        for (Map<String, Object> key : (Iterable<Map<String, Object>>) jwkSetMap.get("keys")) {
            if (tokenKid.equals(key.get("kid"))) {
                keyData = key;
                break;
            }
        }

        if (keyData == null) {
            throw new RuntimeException("Public key not found in JWKS");
        }

        String n = (String) keyData.get("n");
        String e = (String) keyData.get("e");
        byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(e);

        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger exponent = new BigInteger(1, exponentBytes);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);

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
