package tech.aomi.common.web.security.authentication.token;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;

public class TokenAuthenticationConverter implements AuthenticationConverter {

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    public TokenAuthenticationConverter() {
        this(new WebAuthenticationDetailsSource());
    }

    public TokenAuthenticationConverter(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    @Override
    public TokenAuthenticationToken convert(HttpServletRequest request) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (token == null) {
            return null;
        }
        token = token.trim();

        var result = new TokenAuthenticationToken(token);
        result.setDetails(this.authenticationDetailsSource.buildDetails(request));
        return result;
    }

    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }
}
