package com.scamlens.service;

import com.scamlens.dto.RegisterRequest;
import com.scamlens.dto.UserProfileDto;
import com.scamlens.exception.ValidationException;
import com.scamlens.model.User;
import com.scamlens.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;
    private UserService userService;
    private RegisterRequest validRequest;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        userService = new UserService(userRepository, passwordEncoder);
        validRequest = new RegisterRequest("Alex Hunter", "alex@example.com", "SecretPass123", "SecretPass123");
    }

    @Test
    @DisplayName("Should successfully register user with BCrypt password hashing")
    void testRegisterUserSuccess() {
        when(userRepository.existsByEmail("alex@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User u = invocation.getArgument(0);
            u.setId(1L);
            return u;
        });

        User saved = userService.registerUser(validRequest);

        assertNotNull(saved);
        assertEquals("Alex Hunter", saved.getName());
        assertEquals("alex@example.com", saved.getEmail());
        assertNotEquals("SecretPass123", saved.getPassword());
        assertTrue(passwordEncoder.matches("SecretPass123", saved.getPassword()));

        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw ValidationException when duplicate email is registered")
    void testRegisterDuplicateEmail() {
        when(userRepository.existsByEmail("alex@example.com")).thenReturn(true);

        assertThrows(ValidationException.class, () -> userService.registerUser(validRequest));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw ValidationException when passwords do not match")
    void testPasswordMismatch() {
        RegisterRequest mismatch = new RegisterRequest("Alex", "alex@example.com", "Password123", "DifferentPass");

        assertThrows(ValidationException.class, () -> userService.registerUser(mismatch));
    }

    @Test
    @DisplayName("Should update user profile name and password")
    void testUpdateProfile() {
        User user = new User("Old Name", "alex@example.com", passwordEncoder.encode("CurrentPass"));
        when(userRepository.findByEmail("alex@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        UserProfileDto dto = new UserProfileDto();
        dto.setName("New Name");
        dto.setCurrentPassword("CurrentPass");
        dto.setNewPassword("NewSecretPass");
        dto.setConfirmPassword("NewSecretPass");

        User updated = userService.updateProfile("alex@example.com", dto);

        assertEquals("New Name", updated.getName());
        assertTrue(passwordEncoder.matches("NewSecretPass", updated.getPassword()));
    }
}
