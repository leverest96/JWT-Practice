package com.example.test.config;

import com.example.test.exception.handler.AccessDeniedExceptionHandler;
import com.example.test.exception.handler.AuthenticationExceptionHandler;
import com.example.test.properties.jwt.AccessTokenProperties;
import com.example.test.properties.jwt.RefreshTokenProperties;
import com.example.test.properties.security.SecurityCorsProperties;
import com.example.test.repository.MemberRepository;
import com.example.test.repository.RedisBlackListRepository;
import com.example.test.repository.RedisRefreshTokenRepository;
import com.example.test.security.oauth2.handler.OAuth2AuthenticationSuccessHandler;
import com.example.test.security.oauth2.oauth2userdetails.CustomOAuth2UserService;
import com.example.test.security.web.authentication.CustomAuthenticationConverter;
import com.example.test.security.web.authentication.CustomAuthenticationFilter;
import com.example.test.security.web.authentication.CustomAuthenticationProvider;
import com.example.test.security.web.userdetails.MemberDetailsService;
import com.example.test.utility.JwtProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http,
                                                   final CorsConfigurationSource corsConfigurationSource,
                                                   final AuthenticationFilter authenticationFilter,
                                                   final OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService,
                                                   final AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
                                                   final AuthenticationFailureHandler authenticationFailureHandler,
                                                   final AuthenticationEntryPoint authenticationEntryPoint,
                                                   final AccessDeniedHandler accessDeniedHandler) throws Exception {
        http.cors().configurationSource(corsConfigurationSource);

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .rememberMe().disable()
                .logout().disable()
                .headers().disable();

        http.authorizeHttpRequests((authorize) -> authorize
                .requestMatchers(HttpMethod.GET, "/api/member/").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/member/register", "/api/member/login", "/api/member/email/**", "/api/member/removeToken", "/api/member/logout").permitAll()
                .anyRequest().authenticated()
        );

        http.exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler);

        http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);

        http.oauth2Login()
                .authorizationEndpoint()
                .baseUri("/oauth2/authorization")
                .and()
                .redirectionEndpoint()
                .baseUri("/login/oauth2/code/*")
                .and()
                .userInfoEndpoint()
                .userService(oAuth2UserService)
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler);

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(CorsUtils::isPreFlightRequest)
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .requestMatchers(PathRequest.toH2Console());
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(final SecurityCorsProperties properties) {
        final CorsConfiguration corsConfiguration = new CorsConfiguration();

        corsConfiguration.setAllowCredentials(properties.isAllowCredentials());
        corsConfiguration.setAllowedHeaders(properties.getAllowedHeaders());
        corsConfiguration.setAllowedMethods(properties.getAllowedMethods());
        corsConfiguration.setAllowedOrigins(properties.getAllowedOrigins());
        corsConfiguration.setMaxAge(corsConfiguration.getMaxAge());

        final UrlBasedCorsConfigurationSource corsConfigurationSource = new UrlBasedCorsConfigurationSource();

        corsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);

        return corsConfigurationSource;
    }

    @Bean
    public AuthenticationFilter authenticationFilter(final AuthenticationManager authenticationManager,
                                                     final AuthenticationConverter authenticationConverter,
                                                     final AuthenticationSuccessHandler authenticationSuccessHandler,
                                                     final AuthenticationFailureHandler authenticationFailureHandler) {
        final AuthenticationFilter authenticationFilter = new CustomAuthenticationFilter(authenticationManager, authenticationConverter);

        authenticationFilter.setSuccessHandler(authenticationSuccessHandler);
        authenticationFilter.setFailureHandler(authenticationFailureHandler);

        return authenticationFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager(final AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationConverter authenticationConverter() {
        return new CustomAuthenticationConverter();
    }

    @Bean(name = "authenticationSuccessHandler")
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler(final AuthenticationEntryPoint authenticationEntryPoint) {
        return new AuthenticationEntryPointFailureHandler(authenticationEntryPoint);
    }

    @Bean
    public AuthenticationProvider authenticationProvider(final AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService) {
        return new CustomAuthenticationProvider(authenticationUserDetailsService);
    }

    @Bean
    public AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService(
            final @Qualifier("accessTokenProvider") JwtProvider accessTokenProvider
    ) {
        return new MemberDetailsService(accessTokenProvider);
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        return new CustomOAuth2UserService();
    }

    @Bean(name = "oAuth2AuthenticationSuccessHandler")
    public AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler(final MemberRepository memberRepository,
                                                                           final RedisRefreshTokenRepository redisRefreshTokenRepository,
                                                                           final RedisBlackListRepository redisBlackListRepository,
                                                                           final JwtProvider accessTokenProvider,
                                                                           final JwtProvider refreshTokenProvider) {
        return new OAuth2AuthenticationSuccessHandler(memberRepository, redisRefreshTokenRepository, redisBlackListRepository, accessTokenProvider, refreshTokenProvider);
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint(final MemberRepository memberRepository,
                                                             final RedisRefreshTokenRepository redisRefreshTokenRepository,
                                                             final RedisBlackListRepository redisBlackListRepository,
                                                             final JwtProvider accessTokenProvider,
                                                             final JwtProvider refreshTokenProvider,
                                                             final ObjectMapper objectMapper) {
        return new AuthenticationExceptionHandler(memberRepository, redisRefreshTokenRepository, redisBlackListRepository, accessTokenProvider, refreshTokenProvider, objectMapper);
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler(final ObjectMapper objectMapper) {
        return new AccessDeniedExceptionHandler(objectMapper);
    }

    @Bean(name = "accessTokenProvider")
    public JwtProvider accessTokenProvider(final AccessTokenProperties properties) {
        return new JwtProvider(properties);
    }

    @Bean(name = "refreshTokenProvider")
    public JwtProvider refreshTokenProvider(final RefreshTokenProperties properties) {
        return new JwtProvider(properties);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
