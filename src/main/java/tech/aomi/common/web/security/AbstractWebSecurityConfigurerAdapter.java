package tech.aomi.common.web.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import tech.aomi.common.web.security.access.AccessDecisionVoterImpl;
import tech.aomi.common.web.security.access.SecurityServices;
import tech.aomi.common.web.security.authentication.AuthenticationExceptionEntryPoint;

/**
 * 基本web安全配置
 * 项目中继承该类，重写{@link WebSecurityConfigurerAdapter#configure(HttpSecurity)} 时，调用{@code super.configure(http)}
 * 使得配置生效
 * <p>
 * 1. 自动配置-处理无权限结果
 * 2. 自动配置-403响应结果处理。返回标准Result对象
 * 3. 自动配置-自定义权限校验方法实现
 *
 * @author Sean Create At 2019/12/20
 */
public abstract class AbstractWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Autowired(required = false)
    private AccessDeniedHandler accessDeniedHandler;

    @Autowired(required = false)
    private AuthenticationExceptionEntryPoint authenticationExceptionEntryPoint;

    @Autowired(required = false)
    private SecurityServices securityServices;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        if (null != accessDeniedHandler) {
            http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
        }
        if (null != authenticationExceptionEntryPoint) {
            http.exceptionHandling().authenticationEntryPoint(authenticationExceptionEntryPoint);
        }
        if (null != securityServices) {
            http.securityContext().withObjectPostProcessor(new ObjectPostProcessor<AffirmativeBased>() {

                @Override
                public <O extends AffirmativeBased> O postProcess(O object) {
                    object.getDecisionVoters().add(new AccessDecisionVoterImpl(securityServices));
                    return object;
                }

            });
        }
    }
}
