package org.ferhat.advanced_auth_system.security;

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
                System.out.println("No authentication or not authenticated");
                return false;
            }

            Object principal = authentication.getPrincipal();
            System.out.println("Principal class: " + (principal != null ? principal.getClass().getName() : "null"));

            if (principal instanceof UserDetails userDetails) {
                String email = userDetails.getUsername();
                System.out.println("User email from a security context: " + email);

                User user = userRepository.findByEmail(email).orElse(null);
                System.out.println("User from database: " + (user != null ? user.getId() : "not found"));

                return user != null && user.getId().equals(userId);
            }
            return false;
        } catch (Exception e) {
            System.err.println("Error in isCurrentUser: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}
