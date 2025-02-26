package org.ferhat.advanced_auth_system.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.ferhat.advanced_auth_system.core.utils.ApiMessage;
import org.ferhat.advanced_auth_system.dto.request.LoginRequest;
import org.ferhat.advanced_auth_system.dto.request.SignUpRequest;
import org.ferhat.advanced_auth_system.dto.request.TwoFactorVerifyRequest;
import org.ferhat.advanced_auth_system.dto.response.ApiResponse;
import org.ferhat.advanced_auth_system.dto.response.JwtResponse;
import org.ferhat.advanced_auth_system.service.auth.AuthService;
import org.ferhat.advanced_auth_system.service.google_authenticator.TwoFactorAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Identity verification processes")
public class AuthController {
    private final AuthService authService;
    private final TwoFactorAuthService twoFactorAuthService;
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    public AuthController(AuthService authService, TwoFactorAuthService twoFactorAuthService) {
        this.authService = authService;
        this.twoFactorAuthService = twoFactorAuthService;
    }

    @PostMapping("/login")
    @Operation(summary = "User logs in")
    public ResponseEntity<ApiResponse<JwtResponse>> login(@RequestBody LoginRequest loginRequest){
        ApiResponse<JwtResponse> response = authService.login(loginRequest);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PostMapping("/register")
    @Operation(summary = "Registers a new user")
    public ResponseEntity<ApiResponse<String>> register(@RequestBody SignUpRequest signUpRequest){
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

    @PostMapping("/resend-verification")
    @Operation(summary = "Resend verification email")
    public ResponseEntity<ApiResponse<String>> resendVerificationEmail(@RequestParam String email) {
        log.info("Resend verification endpoint çağrıldı: {}", email);
        ApiResponse<String> response = authService.resendVerificationEmail(email);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    // Generate QR Code
    @GetMapping("/2fa/generate/{userId}")
    public ResponseEntity<ApiResponse<String>> generate2FA(@PathVariable Long userId) {
        String qrUrl = twoFactorAuthService.generate2FA(userId);
        if (qrUrl != null) {
            return ResponseEntity.ok(ApiResponse.success(qrUrl, 200, ApiMessage.GENERATED_QR_CODE));
        } else {
            return ResponseEntity.badRequest().body(ApiResponse.error(ApiMessage.USER_NOT_FOUND, 400));
        }
    }

    // 2FA Verification
    @PostMapping("/2fa/verify")
    public ResponseEntity<ApiResponse<String>> verify2FA(@RequestBody TwoFactorVerifyRequest request) {
        ApiResponse<String> response = authService.verify2FA(request);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    // Enable or Disable 2FA
    @PostMapping("/2fa/toggle/{userId}")
    public ResponseEntity<ApiResponse<String>> toggle2FA(@PathVariable Long userId, @RequestParam boolean enable) {
        ApiResponse<String> response = authService.toggle2FA(userId, enable);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

}
