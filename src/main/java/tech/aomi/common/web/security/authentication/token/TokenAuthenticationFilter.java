package tech.aomi.common.web.security.authentication.token;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * @author Sean createAt 2021/10/27
 */
@Setter
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();

    private AuthenticationEntryPoint authenticationEntryPoint;

    private AuthenticationManager authenticationManager;

    private boolean ignoreFailure = false;

    private TokenAuthenticationConverter authenticationConverter = new TokenAuthenticationConverter();
    /**
     * 持久化Context默认不持久化，这里new只是为了代码逻辑正常执行
     */
    private SecurityContextRepository securityContextRepository = new NullSecurityContextRepository();

    public TokenAuthenticationFilter(AuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.authenticationManager = authenticationManager;
        this.ignoreFailure = true;
    }

    public TokenAuthenticationFilter(AuthenticationManager authenticationManager,
                                     AuthenticationEntryPoint authenticationEntryPoint) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
        this.authenticationManager = authenticationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        try {
            TokenAuthenticationToken authRequest = this.authenticationConverter.convert(request);
            if (authRequest == null) {
                this.logger.trace("Did not process authentication request since failed to find token in Authorization header");
                chain.doFilter(request, response);
                return;
            }

            if (authenticationIsRequired(authRequest.getToken())) {
                Authentication authResult = this.authenticationManager.authenticate(authRequest);
                SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(authResult);
                this.securityContextHolderStrategy.setContext(context);
                if (this.logger.isDebugEnabled()) {
                    this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
                }
                // SecurityContextHolderFilter 过滤器会调用securityContextRepository获取
                this.securityContextRepository.saveContext(context, request, response);
            }
        } catch (AuthenticationException ex) {
            this.securityContextHolderStrategy.clearContext();
            this.logger.debug("Failed to process authentication request", ex);
            if (this.ignoreFailure) {
                chain.doFilter(request, response);
            } else {
                this.authenticationEntryPoint.commence(request, response, ex);
            }
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(this.authenticationManager, "An AuthenticationManager is required");
        if (!isIgnoreFailure()) {
            Assert.notNull(this.authenticationEntryPoint, "An AuthenticationEntryPoint is required");
        }
    }

    /**
     * Sets the {@link SecurityContextRepository} to save the {@link SecurityContext} on
     * authentication success. The default action is not to save the
     * {@link SecurityContext}.
     *
     * @param securityContextRepository the {@link SecurityContextRepository} to use.
     *                                  Cannot be null.
     */
    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
        this.securityContextRepository = securityContextRepository;
    }

    protected boolean authenticationIsRequired(String token) {
        // Only reauthenticate if token doesn't match SecurityContextHolder and user
        // isn't authenticated (see SEC-53)
        Authentication existingAuth = this.securityContextHolderStrategy.getContext().getAuthentication();
        if (!(existingAuth instanceof TokenAuthenticationToken) || !existingAuth.isAuthenticated()) {
            return true;
        }
        if (!((TokenAuthenticationToken) existingAuth).getToken().equals(token)) {
            this.logger.info(LogMessage.format("已存在的授权信息中的token与请求的token不匹配 exist=%s, req=%s", ((TokenAuthenticationToken) existingAuth).getToken(), token));
            return true;
        }

        return false;
    }

    protected boolean isIgnoreFailure() {
        return this.ignoreFailure;
    }
}
