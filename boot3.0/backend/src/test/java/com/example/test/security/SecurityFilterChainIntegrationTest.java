package com.example.test.security;

import com.example.test.annotation.ApplicationIntegrationTest;
import com.google.gson.Gson;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ApplicationIntegrationTest
@DisplayName("[SecurityConfig - Integration] securityFilterChain")
public class SecurityFilterChainIntegrationTest {
    @Autowired
    private MockMvc mockMvc;

    private Gson gson;

    @BeforeEach
    void beforeEach() {
        gson = new Gson();
    }

    @Test
    @DisplayName("[Fail] ")
    void failIfAnonymousRequestsReceived() throws Exception {
        // Given
        final String url = "http://localhost:8080/anonymous";

        final String accessToken = "abcd";

        // When
        final ResultActions resultActions = mockMvc.perform(
                MockMvcRequestBuilders.head(url)
                        .cookie(new Cookie("accessToken", accessToken))
        );

        // Then
        resultActions.andExpect(status().isForbidden());
    }
}
