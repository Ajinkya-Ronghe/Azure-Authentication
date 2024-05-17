package com.example.demo;

import com.example.demo.service.SSPService;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Controller
public class DRCSSPController {

    @Autowired
    private SSPService sspService;

    private static final String AUTHORIZATION = "Authorization";
    private static final String BASIC = "Basic ";
    private static final String INTERNAL_ERROR_MSG = "An internal server error occurred.";
    private static final String UNAUTHORIZED_MSG = "Authentication failed. Invalid credentials.";

    @PostMapping("/sspRequest")
    public ResponseEntity<String> handleSSPRequest(@RequestBody String input, HttpServletRequest request) {
        try {
            JSONObject json = new JSONObject();
            sspService.addSSPRequest(input);  // Assuming the method name in service is still relevant
            return ResponseEntity.ok(json.toString());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(INTERNAL_ERROR_MSG);
        }
    }

    @GetMapping("/sspRequestStatus/{uid}")
    public ResponseEntity<String> fetchSSPRequestStatus(@PathVariable String uid, HttpServletRequest request) {
        try {
            String status = sspService.getSSPRequestStatusById(uid);
            JSONObject responseJson = new JSONObject();
            responseJson.put("uid", uid);
            responseJson.put("status", status);
            return ResponseEntity.ok(responseJson.toString());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(INTERNAL_ERROR_MSG);
        }
    }

    private boolean authenticate(String authHeader) {
        if (authHeader != null && authHeader.startsWith(BASIC)) {
            String base64Credentials = authHeader.substring(BASIC.length());
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
            String[] values = credentials.split(":", 2);
            return sspService.authenticate(values[0], values[1]);
        }
        return false;
    }

    // Methods with authentication
    @PostMapping("/authenticatedSSPRequest")
    public ResponseEntity<String> handleAuthenticatedSSPRequest(@RequestBody String input, @RequestHeader(AUTHORIZATION) String authorizationHeader) {
        if (!authenticate(authorizationHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(UNAUTHORIZED_MSG);
        }
        try {
            JSONObject json = new JSONObject();
            sspService.addSSPRequest(input);  // Reuse the same service method for authenticated requests
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(INTERNAL_ERROR_MSG);
        }
    }

    @GetMapping("/authenticatedSSPRequestStatus/{uid}")
    public ResponseEntity<String> fetchAuthenticatedSSPRequestStatus(@PathVariable String uid, @RequestHeader(AUTHORIZATION) String authorizationHeader) {
        if (!authenticate(authorizationHeader)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(UNAUTHORIZED_MSG);
        }
        try {
            String status = sspService.getSSPRequestStatusById(uid);
            JSONObject responseJson = new JSONObject();
            responseJson.put("uid", uid);
            responseJson.put("status", status);
            return ResponseEntity.ok(responseJson.toString());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(INTERNAL_ERROR_MSG);
        }
    }
}
