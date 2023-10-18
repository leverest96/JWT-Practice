package spring.security.boot2.userdetail;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

@RequiredArgsConstructor
@Builder
@Getter
public class CustomOAuth2MemberDetails implements OAuth2User {
    private final Collection<? extends GrantedAuthority> authorities;

    private final Map<String, Object> attributes;

    private final String nameAttributeKey;

    private final String registrationId;

    @Override
    public String getName() {
        return getAttribute(nameAttributeKey);
    }
}
