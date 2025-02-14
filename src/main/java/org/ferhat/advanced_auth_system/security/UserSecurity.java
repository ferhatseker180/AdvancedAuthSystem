package org.ferhat.advanced_auth_system.security;

import lombok.RequiredArgsConstructor;
import org.ferhat.advanced_auth_system.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component("userSecurity")
@RequiredArgsConstructor
public class UserSecurity {

    private final Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public boolean isCurrentUser(Long userId) {
        try {
            Authentication authentication = getAuthentication();
            if (authentication == null) return false;

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User user = (User) userDetails;

            return user.getId().equals(userId);
        } catch (Exception e) {
            return false;
        }
    }
}
