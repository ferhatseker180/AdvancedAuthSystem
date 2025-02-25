package org.ferhat.advanced_auth_system.service.user;

import jakarta.transaction.Transactional;
import org.ferhat.advanced_auth_system.core.config.modelMapper.IModelMapperService;
import org.ferhat.advanced_auth_system.core.utils.ApiMessage;
import org.ferhat.advanced_auth_system.dto.request.PasswordResetRequest;
import org.ferhat.advanced_auth_system.dto.request.UserUpdateRequest;
import org.ferhat.advanced_auth_system.dto.response.ApiResponse;
import org.ferhat.advanced_auth_system.dto.response.UserResponse;
import org.ferhat.advanced_auth_system.model.Role;
import org.ferhat.advanced_auth_system.model.User;
import org.ferhat.advanced_auth_system.repository.RoleRepository;
import org.ferhat.advanced_auth_system.repository.UserRepository;
import org.ferhat.advanced_auth_system.service.auth.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final IModelMapperService modelMapperService;
    private final RoleRepository roleRepository;

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, IModelMapperService modelMapperService, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.modelMapperService = modelMapperService;
        this.roleRepository = roleRepository;
    }

    @Override
    public ApiResponse<UserResponse> getUserById(Long id) {
        return userRepository.findById(id)
                .map(user -> ApiResponse.success(
                        convertToUserResponse(user),
                        HttpStatus.OK.value(),
                        ApiMessage.SUCCESS))
                .orElse(ApiResponse.error(
                        ApiMessage.USER_NOT_FOUND,
                        HttpStatus.NOT_FOUND.value()));
    }

    @Override
    public ApiResponse<UserResponse> getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .map(user -> ApiResponse.success(
                        convertToUserResponse(user),
                        HttpStatus.OK.value(),
                        ApiMessage.SUCCESS))
                .orElse(ApiResponse.error(
                        ApiMessage.USER_NOT_FOUND,
                        HttpStatus.NOT_FOUND.value()));
    }

    @Override
    public ApiResponse<String> updateUser(Long id, UserUpdateRequest userUpdateRequest) {
        try {
            User user = userRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Check if new email is already taken by another user
            if (!user.getEmail().equals(userUpdateRequest.getEmail()) &&
                    userRepository.existsByEmail(userUpdateRequest.getEmail())) {
                return ApiResponse.error(
                        ApiMessage.EMAIL_ALREADY_EXISTS,
                        HttpStatus.BAD_REQUEST.value());
            }

            modelMapperService.forRequest().map(userUpdateRequest, user);

         //   user.setFirstName(userUpdateRequest.getFirstName());
         //   user.setLastName(userUpdateRequest.getLastName());
         //   user.setEmail(userUpdateRequest.getEmail());
         //   user.setUsing2FA(userUpdateRequest.isUsing2FA());

            userRepository.save(user);

            return ApiResponse.success(
                    null,
                    HttpStatus.OK.value(),
                    ApiMessage.SUCCESS);

        } catch (Exception e) {
            return ApiResponse.error(
                    ApiMessage.VALIDATION_ERROR,
                    HttpStatus.BAD_REQUEST.value());
        }
    }

    @Override
    public ApiResponse<String> changePassword(Long id, PasswordResetRequest request) {
        try {
            User user = userRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Verify current password
            if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
                return ApiResponse.error(
                        ApiMessage.UNAUTHORIZED,
                        HttpStatus.UNAUTHORIZED.value());
            }

            // Update password
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);

            return ApiResponse.success(
                    null,
                    HttpStatus.OK.value(),
                    ApiMessage.SUCCESS);

        } catch (Exception e) {
            return ApiResponse.error(
                    ApiMessage.VALIDATION_ERROR,
                    HttpStatus.BAD_REQUEST.value());
        }
    }

    @Override
    public ApiResponse<String> deleteUser(Long id) {
        log.info("User deletion initiated. User ID: {}", id);

        try {
            if (!userRepository.existsById(id)) {
                log.warn("The user to be deleted was not found! ID: {}", id);
                return ApiResponse.error(
                        ApiMessage.USER_NOT_FOUND,
                        HttpStatus.NOT_FOUND.value());
            }

            log.info("User found in the system. ID {}", id);
            userRepository.deleteById(id);
            log.info("User successfully deleted. ID {}", id);

            return ApiResponse.success(
                    null,
                    HttpStatus.OK.value(),
                    ApiMessage.USER_DELETED);

        } catch (Exception e) {
            log.error("Error deleting user! ID: {} Error: {}", id, e.getMessage());
            return ApiResponse.error(
                    ApiMessage.VALIDATION_ERROR,
                    HttpStatus.BAD_REQUEST.value());
        }
    }

    @Override
    public ApiResponse<List<UserResponse>> getAllUsers() {
        try {
            List<User> users = userRepository.findAll();
            List<UserResponse> userResponses = users.stream()
                    .map(this::convertToUserResponse)
                    .collect(Collectors.toList());

            return ApiResponse.success(
                    userResponses,
                    HttpStatus.OK.value(),
                    ApiMessage.SUCCESS);

        } catch (Exception e) {
            return ApiResponse.error(
                    ApiMessage.VALIDATION_ERROR,
                    HttpStatus.BAD_REQUEST.value());
        }
    }

    @Override
    public UserResponse convertToUserResponse(User user) {
        UserResponse userResponse = modelMapperService.forResponse().map(user, UserResponse.class);

        // Map roles separately if they're not automatically mapped
        if (userResponse.getRoles() == null || userResponse.getRoles().isEmpty()) {
            Set<String> roles = user.getRoles().stream()
                    .map(role -> role.getName().name())
                    .collect(Collectors.toSet());
            userResponse.setRoles(roles);
        }

        return userResponse;
    }

    @Transactional
    public Role addRole(String roleName, String description) {
        try {
            // Convert Role name to Enum
            Role.ERole roleEnum = Role.ERole.valueOf(roleName.toUpperCase()); // "ADMIN" -> ERole.ADMIN

            // Add Role into the database
            Role newRole = new Role(roleEnum.name());
            newRole.setDescription(description); // Add Role Description
            return roleRepository.save(newRole); // Save Role
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid role name: " + roleName);
        }
    }
}
