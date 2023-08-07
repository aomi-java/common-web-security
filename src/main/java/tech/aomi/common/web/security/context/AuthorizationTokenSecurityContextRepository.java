package tech.aomi.common.web.security.context;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * 使用http请求头中的AUTHORIZATION作为key
 * 使用map存储SecurityContext
 */
public class AuthorizationTokenSecurityContextRepository implements SecurityContextRepository {

    private final Map<String, SecurityContext> securityContexts = new HashMap<>();

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();
    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        return loadDeferredContext(requestResponseHolder.getRequest()).get();
    }

    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        Supplier<SecurityContext> supplier = () -> getContext(request);
        return new DefaultDeferredSecurityContext(supplier,this.securityContextHolderStrategy);
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (null == token) {
            return;
        }
        securityContexts.put(token, context);
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return getContext(request) != null;
    }

    /**
     * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
     * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
     * @since 5.8
     */
    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }

    private SecurityContext getContext(HttpServletRequest request) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (null == token) {
            return null;
        }
        return securityContexts.get(token);
    }
}

final class DefaultDeferredSecurityContext implements DeferredSecurityContext {
    private final Supplier<SecurityContext> supplier;
    private final SecurityContextHolderStrategy strategy;

    private SecurityContext securityContext;

    private boolean missingContext;

    public DefaultDeferredSecurityContext(Supplier<SecurityContext> supplier, SecurityContextHolderStrategy strategy) {
        this.supplier = supplier;
        this.strategy = strategy;

    }

    @Override
    public boolean isGenerated() {
        init();
        return this.missingContext;
    }

    @Override
    public SecurityContext get() {
        init();
        return this.securityContext;
    }

    private void init() {
        if (this.securityContext != null) {
            return;
        }

        this.securityContext = this.supplier.get();
        this.missingContext = (this.securityContext == null);
        if (this.missingContext) {
            this.securityContext = this.strategy.createEmptyContext();
        }
    }
}