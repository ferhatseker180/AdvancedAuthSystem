package org.ferhat.advanced_auth_system.service.google_authenticator;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.ferhat.advanced_auth_system.model.User;
import org.ferhat.advanced_auth_system.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TwoFactorAuthServiceImpl implements TwoFactorAuthService {
    private final UserRepository userRepository;
    private final GoogleAuthenticator gAuth;

    public TwoFactorAuthServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
        this.gAuth = new GoogleAuthenticator();
    }

    // Generates new 2FA code and QR URL for the user
    @Override
    public String generate2FA(Long userId) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isPresent()) {
            User user = userOpt.get();

            // Generate new 2FA code
            GoogleAuthenticatorKey key = gAuth.createCredentials();
            user.setSecret2FA(key.getKey());  // Save in the user's secret2FA field
            userRepository.save(user);

            // Generate QR code URL for Google Authenticator
            return GoogleAuthenticatorQRGenerator.getOtpAuthURL("AdvancedAuthSystem", user.getEmail(), key);
        }
        return null;
    }

    // Validates the code entered by the user
    @Override
    public boolean verifyCode(Long userId, int code) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            return gAuth.authorize(user.getSecret2FA(), code);
        }
        return false;
    }

    // Enable 2FA
    @Override
    public boolean enable2FA(Long userId) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setUsing2FA(true);
            userRepository.save(user);
            return true;
        }
        return false;
    }


    // Disable 2FA
    @Override
    public boolean disable2FA(Long userId) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setUsing2FA(false);
            user.setSecret2FA(null);
            userRepository.save(user);
            return true;
        }
        return false;
    }
}
