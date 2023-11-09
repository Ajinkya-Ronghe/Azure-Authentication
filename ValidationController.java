package com.example.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ValidationController {

    private static final String TENANT_ID = "your_tenant_id_here"; // Replace with your actual tenant ID

    @GetMapping("/validate")
    public ResponseEntity<String> validateToken(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // Remove "Bearer " prefix
            boolean isValid = OpenIdTokenValidator.validateToken(token, TENANT_ID);
            if (isValid) {
                return ResponseEntity.ok("Token is valid.");
            } else {
                return ResponseEntity.status(401).body("Token is invalid.");
            }
        } else {
            return ResponseEntity.badRequest().body("Missing or malformed Authorization header.");
        }
    }
}
