package org.ferhat.advanced_auth_system.security;

import lombok.RequiredArgsConstructor;
import org.ferhat.advanced_auth_system.model.User;
import org.ferhat.advanced_auth_system.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component("userSecurity")
public class UserSecurity {

    private final UserRepository userRepository;

    public UserSecurity(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    private final Authentication getAuthentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Authentication: " + authentication);
        return authentication;
    }

    public boolean isCurrentUser(Long userId) {
        try {
            Authentication authentication = getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                System.out.println("Kimlik doğrulama yok veya kimlik doğrulanmadı");
                return false;
            }

            Object principal = authentication.getPrincipal();
            System.out.println("Principal sınıfı: " + (principal != null ? principal.getClass().getName() : "null"));

            if (principal instanceof UserDetails userDetails) {
                String email = userDetails.getUsername();
                System.out.println("Güvenlik bağlamından kullanıcı e-postası: " + email);

                User user = userRepository.findByEmail(email).orElse(null);
                System.out.println("Veritabanından kullanıcı: " + (user != null ? user.getId() : "bulunamadı"));

                return user != null && user.getId().equals(userId);
            }
            return false;
        } catch (Exception e) {
            System.err.println("isCurrentUser'da hata: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}
