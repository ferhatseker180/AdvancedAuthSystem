package org.ferhat.advanced_auth_system.service.google_authenticator;

public interface TwoFactorAuthService {
    String generate2FA(Long userId);
    boolean verifyCode(Long userId, int code);
    boolean enable2FA(Long userId);
    boolean disable2FA(Long userId);
}
