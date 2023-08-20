package tech.aomi.common.web.security.authentication.token;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

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
        if (!StringUtils.hasLength(token)) {
            return null;
        }
        token = token.replace("Bearer", "").trim();
        if (token.isEmpty()) {
            return null;
        }

        var result = new TokenAuthenticationToken(token.trim());
        result.setDetails(this.authenticationDetailsSource.buildDetails(request));
        return result;
    }

    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }
}
