package tech.aomi.common.web.security.oauth2;

import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * 启用远程token服务
 *
 * @author Sean createAt 2021/6/9
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(RemoteTokenServicesAutoConfiguration.class)
public @interface EnableRemoteTokenServices {
}
