package tech.aomi.common.web.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import tech.aomi.common.web.security.access.AccessDeniedHandlerImpl;
import tech.aomi.common.web.security.authentication.Http403ForbiddenImpl;

/**
 * web 安全自动配置
 *
 * @author Sean Create At 2019/12/20
 */
@Configuration
public class WebSecurityAutoConfiguration {

    /**
     * json 处理一登录用户的403错误
     */
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new AccessDeniedHandlerImpl();
    }

    /**
     * json 处理未登录用户的403错误
     */
    @Bean
    public Http403ForbiddenEntryPoint http403ForbiddenEntryPoint() {
        return new Http403ForbiddenImpl();
    }

}
