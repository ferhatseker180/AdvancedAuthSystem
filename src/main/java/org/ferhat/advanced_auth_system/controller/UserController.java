package org.ferhat.advanced_auth_system.controller;

import jakarta.validation.Valid;
import org.ferhat.advanced_auth_system.dto.request.PasswordResetRequest;
import org.ferhat.advanced_auth_system.dto.request.UserUpdateRequest;
import org.ferhat.advanced_auth_system.dto.response.ApiResponse;
import org.ferhat.advanced_auth_system.dto.response.UserResponse;
import org.ferhat.advanced_auth_system.service.user.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {
    private final UserService userService;

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
        ApiResponse<String> response = userService.changePassword(id, request);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> deleteUser(@PathVariable Long id) {
        ApiResponse<String> response = userService.deleteUser(id);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserResponse>>> getAllUsers() {
        ApiResponse<List<UserResponse>> response = userService.getAllUsers();
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }
}
