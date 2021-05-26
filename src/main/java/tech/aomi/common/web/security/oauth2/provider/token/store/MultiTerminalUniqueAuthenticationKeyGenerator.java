package tech.aomi.common.web.security.oauth2.provider.token.store;

import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

/**
 * 多终端唯一授权ID生成
 *
 * @author Sean createAt 2021/5/24
 */
public class MultiTerminalUniqueAuthenticationKeyGenerator extends DefaultAuthenticationKeyGenerator {

    private static final String SCOPE = "scope";

    private static final String USERNAME = "username";

    /**
     * AuthenticationKeyGenerator key值生成器 默认情况下根据 username/clientId/scope 参数组合生成唯一token
     * 若想实现，多终端的唯一性登录，只需要使得同一个用户在多个终端生成的 token 一致，
     * 加上上文提到的 createToken 修改逻辑,既去掉extractKey 的 clientId 条件，不区分终端即可
     */
    @Override
    public String extractKey(OAuth2Authentication authentication) {
        Map<String, String> values = new LinkedHashMap<>();
        OAuth2Request authorizationRequest = authentication.getOAuth2Request();
        if (!authentication.isClientOnly()) {
            values.put(USERNAME, authentication.getName());
        }
//        values.put(CLIENT_ID, authorizationRequest.getClientId());
        if (authorizationRequest.getScope() != null) {
            values.put(SCOPE, OAuth2Utils.formatParameterList(new TreeSet<>(authorizationRequest.getScope())));
        }
        return generateKey(values);
    }
}
