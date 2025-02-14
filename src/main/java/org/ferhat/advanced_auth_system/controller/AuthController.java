package org.ferhat.advanced_auth_system.controller;

import org.ferhat.advanced_auth_system.dto.request.LoginRequest;
import org.ferhat.advanced_auth_system.dto.request.SignUpRequest;
import org.ferhat.advanced_auth_system.dto.response.ApiResponse;
import org.ferhat.advanced_auth_system.dto.response.JwtResponse;
import org.ferhat.advanced_auth_system.service.auth.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<JwtResponse>> login(LoginRequest loginRequest){
        ApiResponse<JwtResponse> response = authService.login(loginRequest);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<String>> register(SignUpRequest signUpRequest){
        ApiResponse<String> response = authService.register(signUpRequest);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @GetMapping("/verify")
    public ResponseEntity<ApiResponse<String>> verifyEmail(String token){
        ApiResponse<String> response = authService.verifyEmail(token);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<String>> refreshToken(@RequestParam String token) {
        ApiResponse<String> response = authService.refreshToken(token);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }
}
