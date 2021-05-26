package tech.aomi.common.web.security.oauth2.provider.token.store.mongo;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import java.util.Date;
import java.util.Map;
import java.util.Set;

/**
 * @author Sean createAt 2021/5/24
 */
@Getter
@Setter
@NoArgsConstructor
public class OAuth2AccessTokenEntity implements java.io.Serializable {

    private static final long serialVersionUID = 6925472361897841992L;

    private String id;

    /**
     * 授权id 需要添加索引
     */
    private String authenticationId;

    private String username;
    private String clientId;

    private byte[] authentication;

    /**
     * value 需要添加索引
     */
    private String value;

    private Date expiration;

    private String tokenType;

    private Set<String> scope;

    private Map<String, Object> additionalInformation;

    private String refreshToken;

    /**
     * Create an access token from the value provided.
     */
    public OAuth2AccessTokenEntity(String value) {
        this.value = value;
    }

    /**
     * Copy constructor for access token.
     *
     * @param accessToken
     */
    public OAuth2AccessTokenEntity(OAuth2AccessToken accessToken) {
        this(accessToken.getValue());
        setAdditionalInformation(accessToken.getAdditionalInformation());
        setRefreshToken(accessToken.getRefreshToken());
        setExpiration(accessToken.getExpiration());
        setScope(accessToken.getScope());
        setTokenType(accessToken.getTokenType());
    }

    /**
     * The refresh token associated with the access token, if any.
     *
     * @param refreshToken The refresh token associated with the access token, if any.
     */
    public void setRefreshToken(OAuth2RefreshToken refreshToken) {
        if (null != refreshToken && null != refreshToken.getValue()) {
            this.refreshToken = refreshToken.getValue();
        }
    }
}
