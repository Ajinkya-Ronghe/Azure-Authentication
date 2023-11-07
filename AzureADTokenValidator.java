import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

public class AzureADTokenValidator {

    public static boolean validateToken(String token, String tenant) {
        try {
            // Fetch JWKS keys from Azure AD
            URL jwksUrl = new URL(String.format("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenant));
            HttpURLConnection connection = (HttpURLConnection) jwksUrl.openConnection();
            connection.setRequestMethod("GET");

            // Read the JWKS response
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> response = objectMapper.readValue(connection.getInputStream(), Map.class);
            connection.disconnect();

            // Decode the JWT header
            String[] splitToken = token.split("\\.");
            String headerJson = new String(Base64.getUrlDecoder().decode(splitToken[0]), StandardCharsets.UTF_8);
            Map<String, String> header = objectMapper.readValue(headerJson, Map.class);

            // Find the key with a matching 'kid' value
            String kid = header.get("kid");
            Map<String, String> jwk = null;
            for (Map<String, Object> key : (Iterable<Map<String, Object>>) response.get("keys")) {
                if (kid.equals(key.get("kid"))) {
                    jwk = (Map<String, String>) key;
                    break;
                }
            }

            if (jwk == null) {
                throw new IllegalArgumentException("Unable to find matching JWK for the token 'kid'");
            }

            // Construct the public key
            RSAPublicKey publicKey = (RSAPublicKey) Keys.hmacShaKeyFor(
                Base64.getUrlDecoder().decode((String) jwk.get("n"))
            );

            // Validate the token
            Jws<Claims> jwsClaims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token);

            // Validate the claims as per your requirements
            Claims claims = jwsClaims.getBody();
            // Here you can check issuer, audience, expiration, etc.

            return true; // Token is valid
        } catch (Exception e) {
            e.printStackTrace();
            return false; // Token is invalid
        }
    }

    public static void main(String[] args) {
        String token = "your_token_here"; // Replace with your actual token
        String tenant = "your_tenant_id_here"; // Replace with your actual tenant ID

        boolean isValid = validateToken(token, tenant);
        if (isValid) {
            System.out.println("Token is valid.");
        } else {
            System.out.println("Token is invalid.");
        }
    }
}
