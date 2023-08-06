package tech.aomi.common.web.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import tech.aomi.common.web.security.access.AccessDeniedHandlerImpl;
import tech.aomi.common.web.security.authentication.AuthenticationExceptionEntryPoint;

/**
 * web 安全自动配置
 *
 * @author Sean Create At 2019/12/20
 */
@ConditionalOnProperty(prefix = "aomi-tech.autoconfigure.web.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@Configuration
public class WebSecurityAutoConfiguration {

    /**
     * @return json 处理一登录用户的403错误
     */
    @Bean
    @ConditionalOnMissingBean
    public AccessDeniedHandler accessDeniedHandler() {
        return new AccessDeniedHandlerImpl();
    }

    /**
     * @return json 处理授权异常结果
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthenticationExceptionEntryPoint authenticationExceptionEntryPoint() {
        return new AuthenticationExceptionEntryPoint();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
