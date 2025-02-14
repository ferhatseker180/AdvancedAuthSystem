package org.ferhat.advanced_auth_system.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
public class PasswordResetRequest {

    @NotBlank(message = "Email cant'be empty")
    @Email(message = "Please enter a valid email address")
    private String email;

    @NotBlank(message = "Existing password can't be empty")
    private String currentPassword;

    @NotBlank(message = "The new password can't be empty")
    @Size(min = 8, max = 64, message = "Password must be 8-64 characters long")
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$",
            message = "The password must contain at least one letter and one number")
    private String newPassword;

    public @NotBlank(message = "Email cant' be empty") @Email(message = "Please enter a valid email address") String getEmail() {
        return email;
    }

    public void setEmail(@NotBlank(message = "Email cant' be empty") @Email(message = "Please enter a valid email address") String email) {
        this.email = email;
    }

    public @NotBlank(message = "Existing password can't be empty") String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(@NotBlank(message = "Existing password can't be empty") String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public @NotBlank(message = "The new password can't be empty") @Size(min = 8, max = 64, message = "Password must be 8-64 characters long") String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(@NotBlank(message = "The new password can't be empty") @Size(min = 8, max = 64, message = "Password must be 8-64 characters long") String newPassword) {
        this.newPassword = newPassword;
    }
}
