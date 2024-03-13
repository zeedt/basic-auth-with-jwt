package com.jwt.basic.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class CustomWebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.csrf(it ->  {
            it.ignoringRequestMatchers(
                    "/**"
            ).csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        })
                .authorizeHttpRequests(it->{
                    it.requestMatchers(HttpMethod.POST,  "/login").permitAll();
                    it.requestMatchers("/v3/api-docs/**", "/states/**","/swagger-ui/**","/swagger-ui/**", "/resources/**", "/swagger-resources/**",
                            "/swagger-ui.html", "/swagger-ui/index.html").permitAll();
                    it.anyRequest().authenticated();
                })
                .authenticationManager(authenticationManager)
                .httpBasic(Customizer.withDefaults());
        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}