package com.inferia.backendinferia.security.handler;

import com.inferia.backendinferia.model.User;
import com.inferia.backendinferia.repository.UserRepository;
import com.inferia.backendinferia.security.jwt.JwtTokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Optional;

@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenService jwtTokenService;
    private final UserRepository userRepository;

    private final String redirectUri = "http://localhost:4200/oauth2/callback";

    public OAuth2LoginSuccessHandler(
            JwtTokenService jwtTokenService,
            UserRepository userRepository) {
        this.jwtTokenService = jwtTokenService;
        this.userRepository = userRepository;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = oAuth2User.getAttribute("email");
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            String token = jwtTokenService.generateToken(user);
            String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam("token", token)
                    .build()
                    .toUriString();
            response.sendRedirect(targetUrl);

        } else {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "User OAuth2 not found.");
        }
    }
}