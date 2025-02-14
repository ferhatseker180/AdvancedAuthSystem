package org.ferhat.advanced_auth_system.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
public class UserUpdateRequest {

    @NotBlank(message = "First name can't be empty")
    private String firstName;

    @NotBlank(message = "Last name can't be empty")
    private String lastName;

    @Email(message = "Please enter a valid email address")
    @NotBlank(message = "Email can't be empty")
    private String email;

    private boolean using2FA;

    public @NotBlank(message = "First name can't be empty") String getFirstName() {
        return firstName;
    }

    public void setFirstName(@NotBlank(message = "First name can't be empty") String firstName) {
        this.firstName = firstName;
    }

    public @NotBlank(message = "Last name can't be empty") String getLastName() {
        return lastName;
    }

    public void setLastName(@NotBlank(message = "Last name can't be empty") String lastName) {
        this.lastName = lastName;
    }

    public @Email(message = "Please enter a valid email address") @NotBlank(message = "Email can't be empty") String getEmail() {
        return email;
    }

    public void setEmail(@Email(message = "Please enter a valid email address") @NotBlank(message = "Email can't be empty") String email) {
        this.email = email;
    }

    public boolean isUsing2FA() {
        return using2FA;
    }

    public void setUsing2FA(boolean using2FA) {
        this.using2FA = using2FA;
    }
}
