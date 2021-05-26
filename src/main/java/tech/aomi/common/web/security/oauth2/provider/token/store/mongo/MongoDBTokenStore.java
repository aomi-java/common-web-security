package tech.aomi.common.web.security.oauth2.provider.token.store.mongo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.oauth2.common.*;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Sean createAt 2021/5/24
 */
@Slf4j
public class MongoDBTokenStore implements TokenStore {

    private final String accessTokenCollectionName;

    private final String refreshTokenCollectionName;

    private final MongoTemplate mongoTemplate;

    private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

    public MongoDBTokenStore(MongoTemplate mongoTemplate) {
        this(mongoTemplate, "oAuth2AccessToken", "oAuth2RefreshToken");
    }

    public MongoDBTokenStore(MongoTemplate mongoTemplate, String accessTokenCollectionName, String refreshTokenCollectionName) {
        this.mongoTemplate = mongoTemplate;
        this.accessTokenCollectionName = accessTokenCollectionName;
        this.refreshTokenCollectionName = refreshTokenCollectionName;
    }

    @Override
    public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
        return readAuthentication(token.getValue());
    }

    @Override
    public OAuth2Authentication readAuthentication(String token) {
        return getAuthentication(token);
    }

    @Override
    public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
        removeAccessToken(token.getValue());

        OAuth2AccessTokenEntity entity = new OAuth2AccessTokenEntity(token);
        storeAccessToken(entity, authentication);
    }

    public void storeAccessToken(OAuth2AccessTokenEntity entity, OAuth2Authentication authentication) {
        entity.setAuthenticationId(authenticationKeyGenerator.extractKey(authentication));
        entity.setUsername(authentication.isClientOnly() ? null : authentication.getName());
        entity.setClientId(authentication.getOAuth2Request().getClientId());
        entity.setAuthentication(SerializationUtils.serialize(authentication));
        mongoTemplate.save(entity, this.accessTokenCollectionName);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String tokenValue) {
        OAuth2AccessTokenEntity entity = find(tokenValue);
        if (null == entity)
            return null;

        return getAccessToken(entity);
    }

    @Override
    public void removeAccessToken(OAuth2AccessToken token) {
        if (null == token || !StringUtils.hasLength(token.getValue())) {
            return;
        }
        removeAccessToken(token.getValue());
    }

    @Override
    public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
        OAuth2RefreshTokenEntity entity = new OAuth2RefreshTokenEntity(refreshToken);
        entity.setAuthentication(SerializationUtils.serialize(authentication));
        mongoTemplate.save(entity, refreshTokenCollectionName);
    }

    @Override
    public OAuth2RefreshToken readRefreshToken(String tokenValue) {
        OAuth2RefreshTokenEntity refreshTokenEntity = null;

        try {
            Query query = getQuery(tokenValue);
            refreshTokenEntity = mongoTemplate.findOne(query, OAuth2RefreshTokenEntity.class, refreshTokenCollectionName);
        } catch (Exception e) {
            LOGGER.error("从数据库获取RefreshToken失败", e);
        }
        if (null == refreshTokenEntity)
            return null;
        return new DefaultExpiringOAuth2RefreshToken(refreshTokenEntity.getValue(), refreshTokenEntity.getExpiration());
    }

    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
        Query query = getQuery(token.getValue());
        OAuth2RefreshTokenEntity entity = mongoTemplate.findOne(query, OAuth2RefreshTokenEntity.class, refreshTokenCollectionName);
        if (null == entity)
            return null;
        return getAuthentication(entity.getAuthentication());
    }

    @Override
    public void removeRefreshToken(OAuth2RefreshToken token) {
        Query query = getQuery(token.getValue());
        mongoTemplate.remove(query, refreshTokenCollectionName);
    }

    @Override
    public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
        Criteria criteria = Criteria.where("refreshToken").is(refreshToken.getValue());
        Query query = new Query(criteria);
        mongoTemplate.remove(query, accessTokenCollectionName);
    }

    @Override
    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        String key = authenticationKeyGenerator.extractKey(authentication);

        OAuth2AccessTokenEntity accessTokenEntity = null;
        try {
            accessTokenEntity = findByAuthenticationId(key);
        } catch (Exception e) {
            LOGGER.error("从MongoDB获取 OAuth2AccessToken 失败", e);
        }
        if (accessTokenEntity != null && !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessTokenEntity.getValue())))) {
            removeAccessToken(accessTokenEntity.getValue());
            // Keep the store consistent (maybe the same user is represented by this authentication but the details have
            // changed)
            storeAccessToken(accessTokenEntity, authentication);
        }

        return getAccessToken(accessTokenEntity);
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
        Criteria criteria = Criteria.where("clientId").is(clientId);
        criteria.and("username").is(userName);
        Query query = new Query(criteria);
        List<OAuth2AccessTokenEntity> entities = mongoTemplate.find(query, OAuth2AccessTokenEntity.class, accessTokenCollectionName);
        return entities.parallelStream().map(this::getAccessToken).collect(Collectors.toSet());
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
        Criteria criteria = Criteria.where("clientId").is(clientId);
        Query query = new Query(criteria);

        List<OAuth2AccessTokenEntity> entities = mongoTemplate.find(query, OAuth2AccessTokenEntity.class, accessTokenCollectionName);
        return entities.parallelStream().map(this::getAccessToken).collect(Collectors.toSet());
    }

    public void removeAccessToken(String tokenValue) {
        Query query = getQuery(tokenValue);
        mongoTemplate.remove(query, accessTokenCollectionName);
    }

    public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
        this.authenticationKeyGenerator = authenticationKeyGenerator;
    }

    private OAuth2AccessToken getAccessToken(OAuth2AccessTokenEntity entity) {
        if (null == entity)
            return null;
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(entity.getValue());
        accessToken.setExpiration(entity.getExpiration());
        accessToken.setTokenType(entity.getTokenType());

        if (null != entity.getRefreshToken())
            accessToken.setRefreshToken(new DefaultOAuth2RefreshToken(entity.getRefreshToken()));

        accessToken.setScope(entity.getScope());
        accessToken.setAdditionalInformation(entity.getAdditionalInformation());
        return accessToken;
    }

    private OAuth2Authentication getAuthentication(String tokenValue) {
        OAuth2AccessTokenEntity entity = find(tokenValue);
        if (null == entity)
            return null;

        return getAuthentication(entity.getAuthentication());
    }

    private OAuth2Authentication getAuthentication(byte[] authArr) {
        if (null == authArr)
            return null;
        return SerializationUtils.deserialize(authArr);
    }


    private OAuth2AccessTokenEntity find(String tokenValue) {
        try {
            Query query = getQuery(tokenValue);
            return mongoTemplate.findOne(query, OAuth2AccessTokenEntity.class, accessTokenCollectionName);
        } catch (Exception e) {
            LOGGER.error("从数据库获取AccessToken失败: {}", tokenValue, e);
        }
        return null;
    }

    private OAuth2AccessTokenEntity findByAuthenticationId(String authenticationId) {
        Criteria criteria = Criteria.where("authenticationId").is(authenticationId);
        Query query = new Query(criteria);
        return mongoTemplate.findOne(query, OAuth2AccessTokenEntity.class, accessTokenCollectionName);
    }

    private Query getQuery(String tokenValue) {
        Criteria criteria = Criteria.where("value").is(tokenValue);
        return new Query(criteria);
    }

}
