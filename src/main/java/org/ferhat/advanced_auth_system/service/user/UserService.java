package org.ferhat.advanced_auth_system.service.user;

import org.ferhat.advanced_auth_system.dto.request.PasswordResetRequest;
import org.ferhat.advanced_auth_system.dto.request.UserUpdateRequest;
import org.ferhat.advanced_auth_system.dto.response.ApiResponse;
import org.ferhat.advanced_auth_system.dto.response.UserResponse;
import org.ferhat.advanced_auth_system.model.User;

import java.util.List;

public interface UserService {
    ApiResponse<UserResponse> getUserById(Long id);
    ApiResponse<UserResponse> getUserByEmail(String email);
    ApiResponse<String> updateUser(Long id, UserUpdateRequest userUpdateRequest);
    ApiResponse<String> changePassword(Long id, PasswordResetRequest request);
    ApiResponse<String> deleteUser(Long id);
    ApiResponse<List<UserResponse>> getAllUsers();
    UserResponse convertToUserResponse(User user);
}
