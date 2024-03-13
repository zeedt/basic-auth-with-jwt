package com.jwt.basic.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication(exclude = {SecurityFilterAutoConfiguration.class, DataSourceAutoConfiguration.class})
@EnableMethodSecurity(prePostEnabled = true, proxyTargetClass = true, securedEnabled = true)
@EnableTransactionManagement
@EnableAsync
public class BasicAuthJwtAPp {

    public static void main(String[] args) {
        SpringApplication.run(BasicAuthJwtAPp.class, args);
    }

}
