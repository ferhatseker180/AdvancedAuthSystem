package org.ferhat.advanced_auth_system.service.auth;

import org.ferhat.advanced_auth_system.dto.request.LoginRequest;
import org.ferhat.advanced_auth_system.dto.request.SignUpRequest;
import org.ferhat.advanced_auth_system.dto.response.ApiResponse;
import org.ferhat.advanced_auth_system.dto.response.JwtResponse;
import org.ferhat.advanced_auth_system.model.User;

public interface AuthService {
    ApiResponse<JwtResponse> login(LoginRequest loginRequest);
    ApiResponse<String> register(SignUpRequest signUpRequest);
    ApiResponse<String> verifyEmail(String token);
    ApiResponse<String> refreshToken(String refreshToken);
    void handleFailedLogin(User user);
    ApiResponse<JwtResponse> completeLogin(User user);
    String generateVerificationToken();
}
