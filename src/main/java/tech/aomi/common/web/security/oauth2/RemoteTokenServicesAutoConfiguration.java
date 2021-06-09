package tech.aomi.common.web.security.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import tech.aomi.common.web.security.core.userdetails.UserDetailsService;
import tech.aomi.common.web.security.oauth2.provider.token.UserAuthenticationConverterImpl;

/**
 * @author Sean createAt 2021/5/28
 */
@Configuration
public class RemoteTokenServicesAutoConfiguration {

    @Autowired(required = false)
    private UserDetailsService userDetailsService;

    @Autowired
    private ResourceServerProperties properties;

    @Bean
    @ConditionalOnMissingBean
    public RemoteTokenServices remoteTokenServices() {
        RemoteTokenServices tokenServices = new RemoteTokenServices();
        tokenServices.setClientId(properties.getClientId());
        tokenServices.setClientSecret(properties.getClientSecret());
        tokenServices.setCheckTokenEndpointUrl(properties.getTokenInfoUri());

        UserAuthenticationConverterImpl userAuthenticationConverter = new UserAuthenticationConverterImpl();
        userAuthenticationConverter.setUserDetailsService(userDetailsService);


        DefaultAccessTokenConverter converter = new DefaultAccessTokenConverter();
        converter.setUserTokenConverter(userAuthenticationConverter);
        tokenServices.setAccessTokenConverter(converter);
        return tokenServices;
    }

}
