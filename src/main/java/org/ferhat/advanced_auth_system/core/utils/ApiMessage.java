package org.ferhat.advanced_auth_system.core.utils;

public enum ApiMessage {
    SUCCESS("Operation successful"),
    USER_CREATED("User created successfully"),
    USER_DELETED("User deleted successfully"),
    USER_NOT_FOUND("User not found"),
    LOGIN_SUCCESSFUL("Login successful"),
    LOGIN_FAILED("Invalid email or password"),
    VALIDATION_ERROR("Validation Error"),
    UNAUTHORIZED("Authorization failed"),

    // Auth specific messages
    ACCOUNT_LOCKED("Account is temporarily locked. Please try again later"),
    ACCOUNT_LOCKED_EXTENDED("Account is locked for extended duration due to multiple failed attempts"),
    EMAIL_NOT_VERIFIED("Please verify your email before logging in"),
    EMAIL_ALREADY_EXISTS("Email is already registered"),
    INVALID_CREDENTIALS("Invalid email or password"),
    REGISTRATION_SUCCESS("Registration successful. Please check your email for verification"),
    REGISTRATION_ERROR("Registration failed. Please try again"),
    EMAIL_VERIFICATION_SUCCESS("Email verified successfully"),
    EMAIL_VERIFICATION_ERROR("Email verification failed"),
    INVALID_TOKEN("Invalid or expired token"),
    TOKEN_EXPIRED("Token has expired"),
    TOKEN_REFRESH_SUCCESS("Token refreshed successfully"),
    TOKEN_REFRESH_ERROR("Token refresh failed"),
    TWO_FA_REQUIRED("Two-factor authentication required"),
    TWO_FA_INVALID("Invalid two-factor authentication code"),
    TWO_FA_ENABLED("Two-factor authentication enabled successfully"),
    TWO_FA_DISABLED("Two-factor authentication disabled successfully");

    private final String message;

    ApiMessage(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
