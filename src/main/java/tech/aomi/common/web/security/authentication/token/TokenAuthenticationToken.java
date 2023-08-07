package tech.aomi.common.web.security.authentication.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serial;
import java.util.Collection;

/**
 * token 认证
 *
 * @author Sean createAt 2021/10/27
 */
public class TokenAuthenticationToken extends AbstractAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 5409923538180040235L;

    private final String token;
    private final Object principal;

    private final Object credentials;

    public TokenAuthenticationToken(String token) {
        this(token, null, null, null);
    }

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object.
     */
    public TokenAuthenticationToken(String token, Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.token = token;
    }


    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public String getToken() {
        return token;
    }

}
