package com.jwt.basic.auth.config;

import com.jwt.basic.auth.rsa.RSAUtil;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;

@Slf4j
@Service
public class CustomAuthenticationManager implements AuthenticationManager {

    final PasswordEncoder passwordEncoder;

    final RSAUtil rsaUtil;
    final ObjectMapper objectMapper;

    public CustomAuthenticationManager( RSAUtil rsaUtil) {
        this.rsaUtil = rsaUtil;
        this.passwordEncoder = new BCryptPasswordEncoder(10); // to avoid cyclic bean dependency
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = String.valueOf(authentication.getPrincipal());

        try {
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();

            String[] parts = username.split("\\.");
            String decodedJwt = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode payload = objectMapper.readValue(decodedJwt, JsonNode.class);
            var rolesNode = payload.get("roles");
            var userId = payload.get("id").asText();
            var email = payload.get("email").asText();
            if (!StringUtils.hasText(userId) || !StringUtils.hasText(email))
                throw new BadCredentialsException("Invalid token");

            for (int i=0;i<rolesNode.size();i++) {
                grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_"+rolesNode.get(i).asText()));
            }
            rsaUtil.verifyJwt(username);
            return new UsernamePasswordAuthenticationToken(email, null, grantedAuthorities);
        } catch (TokenExpiredException e) {
            log.error("Token expired due to ", e);
            throw new BadCredentialsException("Token expired");
        } catch (InvalidClaimException | SignatureVerificationException e) {
            log.error("Invalid credentials due to ", e);
            throw new BadCredentialsException("Invalid token");
        } catch (Exception e) {
            log.error("Unable to validate credentials due to ", e);
            throw new BadCredentialsException("Unable to validate user details");
        }


    }

}
