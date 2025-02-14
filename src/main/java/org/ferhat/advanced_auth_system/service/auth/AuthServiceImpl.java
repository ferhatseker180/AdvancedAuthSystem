package org.ferhat.advanced_auth_system.service.auth;

import org.ferhat.advanced_auth_system.core.config.modelMapper.IModelMapperService;
import org.ferhat.advanced_auth_system.core.utils.ApiMessage;
import org.ferhat.advanced_auth_system.dto.request.LoginRequest;
import org.ferhat.advanced_auth_system.dto.request.SignUpRequest;
import org.ferhat.advanced_auth_system.dto.response.ApiResponse;
import org.ferhat.advanced_auth_system.dto.response.JwtResponse;
import org.ferhat.advanced_auth_system.model.Role;
import org.ferhat.advanced_auth_system.model.User;
import org.ferhat.advanced_auth_system.repository.RoleRepository;
import org.ferhat.advanced_auth_system.repository.UserRepository;
import org.ferhat.advanced_auth_system.security.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AuthServiceImpl implements AuthService{

    private static final int INITIAL_MAX_FAILED_ATTEMPTS = 3;
    private static final int EXTENDED_MAX_FAILED_ATTEMPTS = 3;
    private static final long INITIAL_LOCK_DURATION = 15 * 60 * 1000; // 15 minutes
    private static final long EXTENDED_LOCK_DURATION = 30 * 60 * 1000; // 30 minutes
    private static final long VERIFICATION_TOKEN_VALIDITY = 30 * 60 * 1000; // 30 minutes

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final IModelMapperService modelMapperService;

    public AuthServiceImpl(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider, IModelMapperService modelMapperService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.modelMapperService = modelMapperService;
    }

    @Override
    public ApiResponse<JwtResponse> login(LoginRequest loginRequest) {
        try {
            Optional<User> userOptional = userRepository.findByEmail(loginRequest.getEmail());

            if (userOptional.isEmpty()) {
                return ApiResponse.error(ApiMessage.USER_NOT_FOUND, HttpStatus.NOT_FOUND.value());
            }

            User user = userOptional.get();

            // Check if account is locked
            if (!user.isAccountNonLocked()) {
                if (user.getLockTime() != null && new Date().after(user.getLockTime())) {
                    // Unlock account if lock duration has passed
                    user.setAccountNonLocked(true);
                    user.setFailedAttempt(0);
                    user.setLockTime(null);
                    userRepository.save(user);
                } else {
                    ApiMessage message = user.getFailedAttempt() >= EXTENDED_MAX_FAILED_ATTEMPTS
                            ? ApiMessage.ACCOUNT_LOCKED_EXTENDED
                            : ApiMessage.ACCOUNT_LOCKED;
                    return ApiResponse.error(message, HttpStatus.FORBIDDEN.value());
                }
            }

            // Verify password
            if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                handleFailedLogin(user);
                return ApiResponse.error(ApiMessage.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED.value());
            }

            // Check if email is verified
            if (!user.isActiveAccount()) {
                return ApiResponse.error(ApiMessage.EMAIL_NOT_VERIFIED, HttpStatus.FORBIDDEN.value());
            }

            // Check 2FA if enabled
            if (user.isUsing2FA()) {
                JwtResponse twoFaResponse = modelMapperService.forResponse().map(user, JwtResponse.class);
                return ApiResponse.success(twoFaResponse, HttpStatus.OK.value(), ApiMessage.TWO_FA_REQUIRED);
            }

            return completeLogin(user);

        } catch (Exception e) {
            return ApiResponse.error(ApiMessage.LOGIN_FAILED, HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    public ApiResponse<String> register(SignUpRequest signUpRequest) {
        try {
            if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                return ApiResponse.error(ApiMessage.EMAIL_ALREADY_EXISTS, HttpStatus.BAD_REQUEST.value());
            }

            // Map SignUpRequest to User using ModelMapper
            User user = modelMapperService.forRequest().map(signUpRequest, User.class);

            // Set additional fields that aren't in the request
            user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
            user.setAccountNonLocked(true);
            user.setUsing2FA(false);

            // Set default role
            Set<Role> roles = new HashSet<>();
            Role userRole = roleRepository.findByName(Role.ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Default role not found."));
            roles.add(userRole);
            user.setRoles(roles);

            // Generate verification token
            String token = generateVerificationToken();
            user.setVerificationToken(token);
            user.setVerificationTokenExpiry(new Date(System.currentTimeMillis() + VERIFICATION_TOKEN_VALIDITY));

            userRepository.save(user);

            return ApiResponse.success(token, HttpStatus.CREATED.value(), ApiMessage.REGISTRATION_SUCCESS);

        } catch (Exception e) {
            return ApiResponse.error(ApiMessage.REGISTRATION_ERROR, HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    public ApiResponse<String> verifyEmail(String token) {
        try {
            Optional<User> userOptional = userRepository.findByVerificationToken(token);

            if (userOptional.isEmpty()) {
                return ApiResponse.error(ApiMessage.INVALID_TOKEN, HttpStatus.BAD_REQUEST.value());
            }

            User user = userOptional.get();

            // Check if token has expired
            if (user.getVerificationTokenExpiry().before(new Date())) {
                return ApiResponse.error(ApiMessage.TOKEN_EXPIRED, HttpStatus.BAD_REQUEST.value());
            }

            user.setActiveAccount(true);
            user.setVerificationToken(null);
            user.setVerificationTokenExpiry(null);
            userRepository.save(user);

            return ApiResponse.success(null, HttpStatus.OK.value(), ApiMessage.EMAIL_VERIFICATION_SUCCESS);

        } catch (Exception e) {
            return ApiResponse.error(ApiMessage.EMAIL_VERIFICATION_ERROR, HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    public ApiResponse<String> refreshToken(String refreshToken) {
        try {
            if (!jwtTokenProvider.validateToken(refreshToken)) {
                return ApiResponse.error(ApiMessage.INVALID_TOKEN, HttpStatus.BAD_REQUEST.value());
            }

            String email = jwtTokenProvider.getUsernameFromToken(refreshToken);
            String newToken = jwtTokenProvider.generateToken(email);

            return ApiResponse.success(newToken, HttpStatus.OK.value(), ApiMessage.TOKEN_REFRESH_SUCCESS);

        } catch (Exception e) {
            return ApiResponse.error(ApiMessage.TOKEN_REFRESH_ERROR, HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    // Helper methods
    public void handleFailedLogin(User user) {
        int newFailAttempts = user.getFailedAttempt() + 1;
        user.setFailedAttempt(newFailAttempts);

        if (newFailAttempts >= EXTENDED_MAX_FAILED_ATTEMPTS) {
            user.setAccountNonLocked(false);
            user.setLockTime(new Date(System.currentTimeMillis() + EXTENDED_LOCK_DURATION));
        } else if (newFailAttempts >= INITIAL_MAX_FAILED_ATTEMPTS) {
            user.setAccountNonLocked(false);
            user.setLockTime(new Date(System.currentTimeMillis() + INITIAL_LOCK_DURATION));
        }

        userRepository.save(user);
    }

    @Override
    public ApiResponse<JwtResponse> completeLogin(User user) {
        // Reset failed attempts on successful login
        if (user.getFailedAttempt() > 0) {
            user.setFailedAttempt(0);
        }

        // Update last login time
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Generate JWT token
        String token = jwtTokenProvider.generateToken(user.getEmail());

        // Map User to JwtResponse using ModelMapper
        JwtResponse jwtResponse = modelMapperService.forResponse().map(user, JwtResponse.class);
        jwtResponse.setToken(token);
        jwtResponse.setType("Bearer");

        // Add roles if they're not automatically mapped
        if (jwtResponse.getRoles() == null || jwtResponse.getRoles().isEmpty()) {
            List<String> roleNames = user.getRoles().stream()
                    .map(role -> role.getName().name())
                    .collect(Collectors.toList());
            jwtResponse.setRoles(roleNames);
        }

        return ApiResponse.success(jwtResponse, HttpStatus.OK.value(), ApiMessage.LOGIN_SUCCESSFUL);
    }

    @Override
    public String generateVerificationToken() {
        return UUID.randomUUID().toString();
    }
}
