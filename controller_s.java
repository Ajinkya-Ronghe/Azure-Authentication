package com.example.demo;

import com.example.demo.service.SSPService;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
public class DRCSSPController {

    @Autowired
    private SSPService sspService;

    private static final Logger logger = LoggerFactory.getLogger(DRCSSPController.class);
    private static final String AUTHORIZATION = "Authorization";
    private static final String BASIC = "Basic ";
    private static final String INTERNAL_ERROR_MSG = "An internal server error occurred.";
    private static final String UNAUTHORIZED_MSG = "Authentication failed. Invalid credentials.";

    @PostMapping("/sspRequest")
    public ResponseEntity<String> handleSSPRequest(@RequestBody String input, HttpServletRequest request) {
        logger.info("Processing non-authenticated SSP request.");
        try {
            JSONObject json = new JSONObject();
            sspService.addSspRecord(input);  // Assuming this method adds SSP records
            logger.info("SSP request processed successfully.");
            return ResponseEntity.ok(json.toString());
        } catch (Exception e) {
            logger.error("Error processing SSP request: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(INTERNAL_ERROR_MSG);
        }
    }

    @GetMapping("/sspRequestStatus/{uid}")
    public ResponseEntity<String> fetchSSPRequestStatus(@PathVariable String uid, HttpServletRequest request) {
        logger.info("Fetching SSP request status for UID: {}", uid);
        try {
            String status = sspService.getSspRequestStatusById(uid);
            JSONObject responseJson = new JSONObject();
            responseJson.put("uid", uid);
            responseJson.put("status", status);
            logger.info("SSP request status fetched successfully for UID: {}", uid);
            return ResponseEntity.ok(responseJson.toString());
        } catch (Exception e) {
            logger.error("Error fetching SSP request status for UID: {}: {}", uid, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(INTERNAL_ERROR_MSG);
        }
    }

    private boolean authenticate(String authHeader) {
        logger.debug("Attempting authentication.");
        if (authHeader != null && authHeader.startsWith(BASIC)) {
            String base64Credentials = authHeader.substring(BASIC.length());
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
            String[] values = credentials.split(":", 2);
            boolean authenticated = sspService.authenticate(values[0], values[1]);
            logger.debug("Authentication result for user {}: {}", values[0], authenticated);
            return authenticated;
        }
        logger.debug("No authentication attempted, missing or invalid Authorization header.");
        return false;
    }

    // Methods with authentication
    @PostMapping("/authenticatedSSPRequest")
    public ResponseEntity<String> handleAuthenticatedSSPRequest(@RequestBody String input, @RequestHeader(AUTHORIZATION) String authorizationHeader) {
        logger.info("Processing authenticated SSP request.");
        if (!authenticate(authorizationHeader)) {
            logger.warn("Authentication failed for authenticated SSP request.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(UNAUTHORIZED_MSG);
        }
        try {
            JSONObject json = new JSONObject();
            sspService.addSspRecord(input);  // Same service method for consistency
            logger.info("Authenticated SSP request processed successfully.");
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            logger.error("Error processing authenticated SSP request: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(INTERNAL_ERROR_MSG);
        }
    }

    @GetMapping("/authenticatedSSPRequestStatus/{uid}")
    public ResponseEntity<String> fetchAuthenticatedSSPRequestStatus(@PathVariable String uid, @RequestHeader(AUTHORIZATION) String authorizationHeader) {
        logger.info("Fetching authenticated SSP request status for UID: {}", uid);
        if (!authenticate(authorizationHeader)) {
            logger.warn("Authentication failed for fetching SSP request status.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(UNAUTHORIZED_MSG);
        }
        try {
            String status = sspService.getSspRequestStatusById(uid);
            JSONObject responseJson = new JSONObject();
            responseJson.put("uid", uid);
            responseJson.put("status", status);
            logger.info("Authenticated SSP request status fetched successfully for UID: {}", uid);
            return ResponseEntity.ok(responseJson.toString());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(INTERNAL_ERROR_MSG);
        }
    }
}
