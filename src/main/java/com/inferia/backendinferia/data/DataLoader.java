package com.inferia.backendinferia.data;

import com.inferia.backendinferia.model.Role;
import com.inferia.backendinferia.model.User;
import com.inferia.backendinferia.repository.RoleRepository;
import com.inferia.backendinferia.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@Configuration
public class DataLoader {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public DataLoader(PasswordEncoder passwordEncoder,
                      UserRepository userRepository,
                      RoleRepository roleRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Bean
    public CommandLineRunner initTestUser() {
        return args -> {

            Role userRole = roleRepository.findByName("ROLE_USER")
                    .orElseGet(() -> roleRepository.save(new Role("ROLE_USER")));

            final String testEmail = "user@test.com";
            final String testPassword = "test";

            User testUser = userRepository.findByEmail(testEmail).orElseGet(() -> {
                User newTestUser = new User();
                newTestUser.setEmail(testEmail);
                newTestUser.setName("Test User");
                String encryptedPassword = passwordEncoder.encode(testPassword);
                newTestUser.setPassword(encryptedPassword);

                Set<Role> roles = new HashSet<>();
                roles.add(userRole);
                newTestUser.setRoles(roles);

                User savedUser = userRepository.save(newTestUser);

                System.out.println("Test user in H2 initialized:");
                System.out.println("-Email (Username): " + testEmail);
                System.out.println("-Password (Unencrypted): " + testPassword);
                System.out.println("-Hash BCrypt: " + encryptedPassword);

                return savedUser;
            });
        };
    }
}