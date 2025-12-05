package com.inferia.backendinferia.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.inferia.backendinferia.model.User;
import com.inferia.backendinferia.repository.UserRepository;
import com.inferia.backendinferia.security.jwt.JwtTokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Component
public class UsernamePasswordSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenService jwtTokenService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    public UsernamePasswordSuccessHandler(
            JwtTokenService jwtTokenService,
            UserRepository userRepository,
            ObjectMapper objectMapper) {
        this.jwtTokenService = jwtTokenService;
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        String email = authentication.getName();
        Optional<User> userOptional = userRepository.findByEmail(email);

        String redirectUri = "http://localhost:4200/oauth2/callback";
        if (userOptional.isPresent()) {
            User user = userOptional.get();

            String token = jwtTokenService.generateToken(user);
            String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam("token", token)
                    .build().toUriString();
            getRedirectStrategy().sendRedirect(request, response, targetUrl);

        } else {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "User not found after auth");
        }
    }
}