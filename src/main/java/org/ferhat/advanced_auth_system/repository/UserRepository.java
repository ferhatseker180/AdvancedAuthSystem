package org.ferhat.advanced_auth_system.repository;

import org.ferhat.advanced_auth_system.model.Role;
import org.ferhat.advanced_auth_system.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // Find User with email
    Optional<User> findByEmail(String email);

    // Check email
    boolean existsByEmail(String email);

    // Find active Users
    List<User> findByIsActiveAccountTrue();

    // Find users with a specific role
    List<User> findByRoles_Name(Role.ERole roleName);

    // Sorting by last entry date
    List<User> findByOrderByLastLoginAtDesc();

    // Users with unlocked accounts
    List<User> findByAccountNonLockedTrue();

    // Users with verification tokens
    Optional<User> findByVerificationToken(String token);

}
