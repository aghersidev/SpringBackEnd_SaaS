package com.inferia.backendinferia.security.oauth2;

import com.inferia.backendinferia.model.Role;
import com.inferia.backendinferia.model.User;
import com.inferia.backendinferia.repository.RoleRepository;
import com.inferia.backendinferia.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public CustomOAuth2UserService(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String sub = oAuth2User.getAttribute("sub");
        Integer githubIdInt = oAuth2User.getAttribute("id");
        String login = oAuth2User.getAttribute("login");
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        String providerId;
        if (sub != null) {
            providerId = sub;
        } else if (githubIdInt != null) {
            providerId = githubIdInt.toString();
        } else {
            throw new OAuth2AuthenticationException("No provider ID found");
        }
        if (email == null) {
            email = "oauth_" + providerId + "@no-email.local";
        }
        if (name == null) {
            name = (login != null) ? login : providerId;
        }

        String userNameAttributeName =
                userRequest.getClientRegistration()
                        .getProviderDetails()
                        .getUserInfoEndpoint()
                        .getUserNameAttributeName();

        User user = processOAuth2User(email, name);

        Collection<? extends GrantedAuthority> authorities =
                user.getRoles().stream()
                        .map(r -> new SimpleGrantedAuthority(r.getName()))
                        .collect(Collectors.toSet());
        Map<String, Object> mappedAttributes = new HashMap<>(oAuth2User.getAttributes());
        mappedAttributes.put("email", user.getEmail());

        return new DefaultOAuth2User(
                authorities,
                mappedAttributes,
                userNameAttributeName
        );
    }

    private User processOAuth2User(String email, String name) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
        } else {
            user = new User();
            user.setEmail(email);
            user.setName(name);

            Role userRole = roleRepository.findByName("ROLE_USER")
                    .orElseThrow(() -> new IllegalStateException("Role ROLE_USER doesnt exist"));

            user.setRoles(Set.of(userRole));
            userRepository.save(user);
        }
        return user;
    }
}
