package com.example.test.config;

import com.example.test.properties.security.SecurityCorsProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {
    private final SecurityCorsProperties properties;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        List<String> allowedOrigins = properties.getAllowedOrigins();
        List<String> allowedMethods = properties.getAllowedMethods();
        List<String> allowedHeaders = properties.getAllowedHeaders();

        registry.addMapping("/**")
                .allowCredentials(properties.isAllowCredentials())
                .allowedOrigins(allowedOrigins.toArray(new String[0]))
                .allowedMethods(allowedMethods.toArray(new String[0]))
                .allowedHeaders(allowedHeaders.toArray(new String[0]));
    }
}
