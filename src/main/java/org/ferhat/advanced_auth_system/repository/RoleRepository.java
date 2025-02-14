package org.ferhat.advanced_auth_system.repository;

import org.ferhat.advanced_auth_system.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    // Finding by Role name
    Optional<Role> findByName(Role.ERole name);

    // Finding active roles
    List<Role> findByIsActiveTrue();

    // Find roles with a specific description
    List<Role> findByDescriptionContaining(String description);

}
