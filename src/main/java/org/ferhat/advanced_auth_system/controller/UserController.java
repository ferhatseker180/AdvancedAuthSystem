package org.ferhat.advanced_auth_system.controller;

import jakarta.validation.Valid;
import org.ferhat.advanced_auth_system.dto.request.PasswordResetRequest;
import org.ferhat.advanced_auth_system.dto.request.UserUpdateRequest;
import org.ferhat.advanced_auth_system.dto.response.ApiResponse;
import org.ferhat.advanced_auth_system.dto.response.UserResponse;
import org.ferhat.advanced_auth_system.model.Role;
import org.ferhat.advanced_auth_system.service.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {
    private final UserService userService;

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isCurrentUser(#id)")
    public ResponseEntity<ApiResponse<UserResponse>> getUserById(@PathVariable Long id) {
        ApiResponse<UserResponse> response = userService.getUserById(id);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @GetMapping("/email/{email}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<UserResponse>> getUserByEmail(@PathVariable String email) {
        ApiResponse<UserResponse> response = userService.getUserByEmail(email);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userSecurity.isCurrentUser(#id)")
    public ResponseEntity<ApiResponse<String>> updateUser(
            @PathVariable Long id,
            @Valid @RequestBody UserUpdateRequest userUpdateRequest) {
        ApiResponse<String> response = userService.updateUser(id, userUpdateRequest);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PutMapping("/{id}/password")
    @PreAuthorize("@userSecurity.isCurrentUser(#id)")
    public ResponseEntity<ApiResponse<String>> changePassword(
            @PathVariable Long id,
            @Valid @RequestBody PasswordResetRequest request) {
        log.info("Password change request received. User ID: {}", id);
        ApiResponse<String> response = userService.changePassword(id, request);
        log.info("Password change is complete: ID = {} - Status Code: {}",
                id, response.getStatusCode());
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> deleteUser(@PathVariable Long id) {
        log.info("DELETE request received. User will be deleted: ID = {}", id);
        ApiResponse<String> response = userService.deleteUser(id);
        log.info("User deletion completed: ID = {} - Result: {}", id, response.getMessage());
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserResponse>>> getAllUsers() {
        ApiResponse<List<UserResponse>> response = userService.getAllUsers();
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PostMapping("/add-role")
    public ResponseEntity<String> addRole(@RequestParam String roleName, @RequestParam String description) {
        try {
            Role addedRole = userService.addRole(roleName, description);
            return ResponseEntity.ok("Role added successfully: " + addedRole.getName());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error while adding role: " + e.getMessage());
        }
    }
}
