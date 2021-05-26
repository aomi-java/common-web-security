package tech.aomi.common.web.security.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.error.OAuth2ExceptionRenderer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * 基础资源服务器配置
 * <p>
 * 1. tokenstore 自动配置
 * 2. 自定义异常渲染
 * 3. 自定义权限拒绝受理
 *
 * @author Sean Create At 2019/12/20
 */
public class AbstractResourceServerConfigurerAdapter extends ResourceServerConfigurerAdapter {

    @Autowired(required = false)
    private TokenStore tokenStore;

    @Autowired(required = false)
    private OAuth2ExceptionRenderer oAuth2ExceptionRenderer;

    @Autowired(required = false)
    private AccessDeniedHandler accessDeniedHandler;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        if (null != tokenStore) {
            resources.tokenStore(tokenStore);
        }
        if (null != oAuth2ExceptionRenderer) {
            resources.authenticationEntryPoint(oAuth2AuthenticationEntryPoint());
        }
        if (null != accessDeniedHandler) {
            resources.accessDeniedHandler(accessDeniedHandler);
        }
    }

    /**
     * 设置异常渲染服务
     */
    protected OAuth2AuthenticationEntryPoint oAuth2AuthenticationEntryPoint() {
        OAuth2AuthenticationEntryPoint oAuth2AuthenticationEntryPoint = new OAuth2AuthenticationEntryPoint();
        oAuth2AuthenticationEntryPoint.setExceptionRenderer(oAuth2ExceptionRenderer);
        return oAuth2AuthenticationEntryPoint;
    }
}
