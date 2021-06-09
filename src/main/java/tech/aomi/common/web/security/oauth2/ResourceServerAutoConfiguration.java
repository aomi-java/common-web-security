package tech.aomi.common.web.security.oauth2;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.error.OAuth2ExceptionRenderer;
import tech.aomi.common.web.security.oauth2.provider.error.OAuth2ExceptionRendererImpl;

/**
 * @author Sean createAt 2021/5/26
 */
@ConditionalOnProperty(prefix = "aomi-tech.autoconfigure.web.security.oauth2", name = "enabled", havingValue = "true", matchIfMissing = true)
@Configuration
public class ResourceServerAutoConfiguration {

    /**
     * OAuth2Exception异常处理服务
     */
    @Bean
    public OAuth2ExceptionRenderer oAuth2ExceptionRenderer() {
        return new OAuth2ExceptionRendererImpl();
    }


}
