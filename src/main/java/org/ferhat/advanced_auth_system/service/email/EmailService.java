package org.ferhat.advanced_auth_system.service.email;

public interface EmailService {

    void sendVerificationEmail(String to, String token);
}
