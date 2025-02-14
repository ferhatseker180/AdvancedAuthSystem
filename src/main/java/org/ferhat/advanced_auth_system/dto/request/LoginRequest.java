package org.ferhat.advanced_auth_system.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {

    @NotBlank(message = "Email cant'be be empty!!")
    @Email(message = "Please enter a valid email address")
    private String email;

    @NotBlank(message = "Password can't be empty!!")
    private String password;

    public @NotBlank(message = "Email cant'be be empty!!") @Email(message = "Please enter a valid email address") String getEmail() {
        return email;
    }

    public void setEmail(@NotBlank(message = "Email cant'be be empty!!") @Email(message = "Please enter a valid email address") String email) {
        this.email = email;
    }

    public @NotBlank(message = "Password can't be empty!!") String getPassword() {
        return password;
    }

    public void setPassword(@NotBlank(message = "Password can't be empty!!") String password) {
        this.password = password;
    }
}
