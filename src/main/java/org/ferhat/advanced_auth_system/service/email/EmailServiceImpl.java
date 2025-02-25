package org.ferhat.advanced_auth_system.service.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.ferhat.advanced_auth_system.service.auth.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    public EmailServiceImpl(JavaMailSender mailSender) {
        this.mailSender = mailSender;

    }

    @Override
    public void sendVerificationEmail(String to, String token) {
        log.info("A confirmation email is being sent: {}", to);

        String verificationLink = "http://localhost:8080/api/v1/auth/verify?token=" + token;

        // Email content in HTML format
        String emailContent = "<h2>Click on the following link to verify your account:</h2>"
                + "<p><a href=\"" + verificationLink + "\" target=\"_blank\">" + verificationLink + "</a></p>"
                + "<p>This connection link is only valid for a certain period of time.</p>";

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(to);
            helper.setSubject("Account Verification");
            helper.setText(emailContent, true); // The second parameter must be true, because we are sending HTML content.

            mailSender.send(message);
            log.info("The email was sent successfully: {}", to);
        } catch (MessagingException e) {
            log.error("Email sending error: {}", e.getMessage());
            throw new RuntimeException("Failed to send email.", e);
        }
    }

}
