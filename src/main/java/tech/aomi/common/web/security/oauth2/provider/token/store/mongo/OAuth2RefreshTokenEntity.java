package tech.aomi.common.web.security.oauth2.provider.token.store.mongo;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import java.util.Date;

/**
 * @author Sean createAt 2021/5/25
 */
@Getter
@Setter
@NoArgsConstructor
public class OAuth2RefreshTokenEntity implements java.io.Serializable {

    private static final long serialVersionUID = -1449922286693188039L;

    private String id;

    private String authenticationId;

    private byte[] authentication;

    private String value;

    private Date expiration;

    public OAuth2RefreshTokenEntity(OAuth2RefreshToken token) {
        this.value = token.getValue();
        if (token instanceof ExpiringOAuth2RefreshToken) {
            this.expiration = ((ExpiringOAuth2RefreshToken) token).getExpiration();
        }
    }
}
