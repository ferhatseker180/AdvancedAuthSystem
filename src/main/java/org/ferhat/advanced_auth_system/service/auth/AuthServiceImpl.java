package org.ferhat.advanced_auth_system.service.auth;

import org.ferhat.advanced_auth_system.core.config.modelMapper.IModelMapperService;
import org.ferhat.advanced_auth_system.core.utils.ApiMessage;
import org.ferhat.advanced_auth_system.dto.request.LoginRequest;
import org.ferhat.advanced_auth_system.dto.request.SignUpRequest;
import org.ferhat.advanced_auth_system.dto.request.TwoFactorVerifyRequest;
import org.ferhat.advanced_auth_system.dto.response.ApiResponse;
import org.ferhat.advanced_auth_system.dto.response.JwtResponse;
import org.ferhat.advanced_auth_system.model.Role;
import org.ferhat.advanced_auth_system.model.User;
import org.ferhat.advanced_auth_system.repository.RoleRepository;
import org.ferhat.advanced_auth_system.repository.UserRepository;
import org.ferhat.advanced_auth_system.security.JwtTokenProvider;
import org.ferhat.advanced_auth_system.service.email.EmailService;
import org.ferhat.advanced_auth_system.service.google_authenticator.TwoFactorAuthServiceImpl;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class AuthServiceImpl implements AuthService{

    private static final int INITIAL_MAX_FAILED_ATTEMPTS = 3;
    private static final int EXTENDED_MAX_FAILED_ATTEMPTS = 3;
    private static final long INITIAL_LOCK_DURATION = 15 * 60 * 1000; // 15 minutes
    private static final long EXTENDED_LOCK_DURATION = 30 * 60 * 1000; // 30 minutes
    private static final long VERIFICATION_TOKEN_VALIDITY = 60 * 60 * 1000; // 60 minutes

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final IModelMapperService modelMapperService;
    private final EmailService emailService;
    private final TwoFactorAuthServiceImpl twoFactorAuthService;

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    public AuthServiceImpl(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider, IModelMapperService modelMapperService, EmailService emailService, TwoFactorAuthServiceImpl twoFactorAuthService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.modelMapperService = modelMapperService;
        this.emailService = emailService;
        this.twoFactorAuthService = twoFactorAuthService;
    }

    @Override
    public ApiResponse<JwtResponse> login(LoginRequest loginRequest) {
        try {
            log.info("Login attempt for email: {}", loginRequest.getEmail());

            Optional<User> userOptional = userRepository.findByEmail(loginRequest.getEmail());

            if (userOptional.isEmpty()) {
                log.warn("Login failed: User not found for email: {}", loginRequest.getEmail());
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
                    log.info("Account unlocked for email: {}", loginRequest.getEmail());
                } else {
                    ApiMessage message = user.getFailedAttempt() >= EXTENDED_MAX_FAILED_ATTEMPTS
                            ? ApiMessage.ACCOUNT_LOCKED_EXTENDED
                            : ApiMessage.ACCOUNT_LOCKED;
                    log.warn("Login failed: Account is locked for email: {}", loginRequest.getEmail());
                    return ApiResponse.error(message, HttpStatus.FORBIDDEN.value());
                }
            }

            // Verify password
            if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                handleFailedLogin(user);
                log.warn("Login failed: Invalid credentials for email: {}", loginRequest.getEmail());
                return ApiResponse.error(ApiMessage.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED.value());
            }

            // Check if email is verified
            if (!user.isActiveAccount()) {
                log.warn("Login failed: Email not verified for email: {}", loginRequest.getEmail());
                return ApiResponse.error(ApiMessage.EMAIL_NOT_VERIFIED, HttpStatus.FORBIDDEN.value());
            }

            // Check 2FA if enabled
            if (user.isUsing2FA()) {
                JwtResponse twoFaResponse = modelMapperService.forResponse().map(user, JwtResponse.class);
                log.info("2FA required for email: {}", loginRequest.getEmail());
                return ApiResponse.success(twoFaResponse, HttpStatus.OK.value(), ApiMessage.TWO_FA_REQUIRED);
            }

            ApiResponse<JwtResponse> response = completeLogin(user);
            log.info("Login successful for email: {}", loginRequest.getEmail());
            return response;

        } catch (Exception e) {
            log.error("Unexpected error during login for email: {}", loginRequest.getEmail(), e);
            return ApiResponse.error(ApiMessage.LOGIN_FAILED, HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    public ApiResponse<String> register(SignUpRequest signUpRequest) {
        try {
            String email = signUpRequest.getEmail().trim();

            if (userRepository.existsByEmail(email)) {
                return ApiResponse.error(ApiMessage.EMAIL_ALREADY_EXISTS, HttpStatus.BAD_REQUEST.value());
            }

            // Create User
            User user = modelMapperService.forRequest().map(signUpRequest, User.class);
            user.setId(null);
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
            user.setAccountNonLocked(true);
            user.setUsing2FA(false);

            // Determine the user's role
            Role role;
            if (signUpRequest.getRoleId() == null) {
                //  If roleId is null, the USER role is assigned by default
                role = roleRepository.findByName(Role.ERole.ROLE_USER)
                        .orElseThrow(() -> new IllegalStateException(ApiMessage.USER_NOT_FOUND.getMessage()));
            } else {
                // Find role with sent ID
                role = roleRepository.findById(signUpRequest.getRoleId())
                        .orElseThrow(() -> new RuntimeException("Role not found with ID: " + signUpRequest.getRoleId()));
            }
            user.setRoles(Set.of(role));

            // Create a verification token
            String token = generateVerificationToken();
            user.setVerificationToken(token);
            user.setVerificationTokenExpiry(new Date(System.currentTimeMillis() + VERIFICATION_TOKEN_VALIDITY));

            userRepository.save(user);

            return ApiResponse.success(token, HttpStatus.CREATED.value(), ApiMessage.REGISTRATION_SUCCESS);

        } catch (IllegalStateException e) {
            log.error("An error occurred during user registration: {}", e.getMessage());
            return ApiResponse.error(ApiMessage.USER_NOT_FOUND, HttpStatus.NOT_FOUND.value());

        } catch (Exception e) {
            log.error("Unexpected error during user registration: {}", e.getMessage(), e);
            return ApiResponse.error(ApiMessage.REGISTRATION_ERROR, HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }


    @Override
    public ApiResponse<String> verifyEmail(String token) {
        try {
            log.info("Email verification attempt with token: {}", token);
            Optional<User> userOptional = userRepository.findByVerificationToken(token);

            if (userOptional.isEmpty()) {
                log.warn("Email verification failed: Invalid token");
                return ApiResponse.error(ApiMessage.INVALID_TOKEN, HttpStatus.BAD_REQUEST.value());
            }

            User user = userOptional.get();

            // Check if token has expired
            if (user.getVerificationTokenExpiry() == null || user.getVerificationTokenExpiry().before(new Date())) {
                log.warn("Email verification failed: Token expired for user {}", user.getEmail());
                return ApiResponse.error(ApiMessage.TOKEN_EXPIRED, HttpStatus.BAD_REQUEST.value());
            }

            user.setActiveAccount(true);
            user.setVerificationToken(null);
            user.setVerificationTokenExpiry(null);
            userRepository.save(user);

            log.info("Email verified successfully for user {}", user.getEmail());
            return ApiResponse.success(null, HttpStatus.OK.value(), ApiMessage.EMAIL_VERIFICATION_SUCCESS);

        } catch (Exception e) {
            log.error("Unexpected error during email verification", e);
            return ApiResponse.error(ApiMessage.EMAIL_VERIFICATION_ERROR, HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    public ApiResponse<String> resendVerificationEmail(String email) {
        log.info("Request to resend the verification email: {}", email);

        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            log.warn("User Not Found: {}", email);
            return ApiResponse.error(ApiMessage.USER_NOT_FOUND, HttpStatus.NOT_FOUND.value());
        }

        User user = userOptional.get();

        // If the account is already verified, there is no need to send an email again
        if (user.isActiveAccount()) {
            log.info("The user is already verified: {}", email);
            return ApiResponse.error(ApiMessage.EMAIL_ALREADY_VERIFIED, HttpStatus.BAD_REQUEST.value());
        }

        // We added a log before resetting the token to avoid NULL token error
        log.info("Available Token: {}", user.getVerificationToken());

        // Create a new token in each case
        String newToken = generateVerificationToken();
        user.setVerificationToken(newToken);
        user.setVerificationTokenExpiry(new Date(System.currentTimeMillis() + VERIFICATION_TOKEN_VALIDITY));

        // Save
        userRepository.save(user);

        // Verify by adding the log again after saving
        log.info("New Token: {}", user.getVerificationToken());

        // ✅ Send new token with email
        emailService.sendVerificationEmail(user.getEmail(), newToken);

        return ApiResponse.success("New verification email sent", HttpStatus.OK.value(), ApiMessage.VERIFICATION_EMAIL_SENT);
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
    public ApiResponse<String> verify2FA(TwoFactorVerifyRequest request) {
        boolean isValid = twoFactorAuthService.verifyCode(request.getUserId(), request.getCode());
        if (isValid) {
            return ApiResponse.success(null, HttpStatus.OK.value(), ApiMessage.TWO_FA_ENABLED);
        } else {
            return ApiResponse.error(ApiMessage.INVALID_TWO_FA_CODE, HttpStatus.BAD_REQUEST.value());
        }
    }

    @Override
    public ApiResponse<String> toggle2FA(Long userId, boolean enable) {
        boolean success = enable ? twoFactorAuthService.enable2FA(userId) : twoFactorAuthService.disable2FA(userId);
        if (success) {
            return ApiResponse.success(null, HttpStatus.OK.value(), enable ? ApiMessage.TWO_FA_ENABLED : ApiMessage.TWO_FA_DISABLED);
        } else {
            return ApiResponse.error(ApiMessage.USER_NOT_FOUND, HttpStatus.NOT_FOUND.value());
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
