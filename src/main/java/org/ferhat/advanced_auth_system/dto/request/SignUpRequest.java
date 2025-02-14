package org.ferhat.advanced_auth_system.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
public class SignUpRequest {

    @NotBlank(message = "Email can'be empty!!")
    @Email(message = "Enter a valid email address")
    private String email;

    @NotBlank(message = "Password can't be empty!!")
    @Size(min = 8, max = 64, message = "Password must be 8-64 characters long")
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$",
            message = "The password must contain at least one letter and one number")
    private String password;

    @NotBlank(message = "First name can't be empty!!")
    private String firstName;

    @NotBlank(message = "Lastname can't be empty")
    private String lastName;

    private Set<String> roles;

    public @NotBlank(message = "Email can'be empty!!") @Email(message = "Enter a valid email address") String getEmail() {
        return email;
    }

    public void setEmail(@NotBlank(message = "Email can'be empty!!") @Email(message = "Enter a valid email address") String email) {
        this.email = email;
    }

    public @NotBlank(message = "Password can't be empty!!") @Size(min = 8, max = 64, message = "Password must be 8-64 characters long") String getPassword() {
        return password;
    }

    public void setPassword(@NotBlank(message = "Password can't be empty!!") @Size(min = 8, max = 64, message = "Password must be 8-64 characters long") String password) {
        this.password = password;
    }

    public @NotBlank(message = "First name can't be empty!!") String getFirstName() {
        return firstName;
    }

    public void setFirstName(@NotBlank(message = "First name can't be empty!!") String firstName) {
        this.firstName = firstName;
    }

    public @NotBlank(message = "Lastname can't be empty") String getLastName() {
        return lastName;
    }

    public void setLastName(@NotBlank(message = "Lastname can't be empty") String lastName) {
        this.lastName = lastName;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }
}
