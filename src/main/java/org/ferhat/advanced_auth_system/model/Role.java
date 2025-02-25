package org.ferhat.advanced_auth_system.model;

import jakarta.persistence.*;

@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(length = 20, unique = true)
    private ERole name;

    @Column(nullable = false)
    private String description;

    @Column(nullable = false)
    private boolean isActive = true;

    // Default constructor
    public Role() {}

        public Role(String name) {
        this.name = ERole.valueOf(name);
        this.description = name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public ERole getName() {
        return name;
    }

    public void setName(ERole name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
    }

    @Override
    public String toString() {
        return "Role{name=" + name + ", description='" + description + "', isActive=" + isActive + "}";
    }

    public enum ERole {
        USER,        // Standard User
        ADMIN       // Full Authorization
    }
}
