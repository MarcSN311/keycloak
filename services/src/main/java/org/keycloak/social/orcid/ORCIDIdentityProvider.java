/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.orcid;

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.JsonWebToken;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;

/**
 * @author Marc Schulz-Narres
 */
public class ORCIDIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<ORCIDIdentityProviderConfig> {

    public static final String AUTH_URL = "https://orcid.org/oauth/authorize";
    public static final String TOKEN_URL = "https://orcid.org/oauth/token";
    public static final String PROFILE_URL = "https://orcid.org/oauth/userinfo";
    public static final String DEFAULT_SCOPE = "openid email /read-limited";

    public ORCIDIdentityProvider(KeycloakSession session, ORCIDIdentityProviderConfig config) {
        super(session, config);
		config.setAuthorizationUrl(config.targetSandbox() ? "https://sandbox.orcid.org/oauth/authorize" : AUTH_URL);
		config.setTokenUrl((config.targetSandbox() ? "https://sandbox.orcid.org/oauth/token" : BASE_URL) + TOKEN_RESOURCE);
		config.setUserInfoUrl((config.targetSandbox() ? "https://sandbox.orcid.org/oauth/userinfo" : BASE_URL) + PROFILE_RESOURCE);
    }

	@Override
	protected String getDefaultScopes() {
		return DEFAULT_SCOPE;
	}

    @Override
    protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken, JsonWebToken idToken) throws IOException {
        String id = idToken.getSubject();
        BrokeredIdentityContext identity = new BrokeredIdentityContext(id);
        BrokeredIdentityContext identityNew;
        String name = (String) idToken.getOtherClaims().get(IDToken.NAME);
        String preferredUsername = (String) idToken.getOtherClaims().get(getusernameClaimNameForIdToken());
        String email = (String) idToken.getOtherClaims().get(IDToken.EMAIL);

        if (!getConfig().isDisableUserInfoService()) {
            String userInfoUrl = getUserInfoUrl();
            if (userInfoUrl != null && !userInfoUrl.isEmpty() && (id == null || name == null || preferredUsername == null || email == null)) {
                if (accessToken != null) {
                    JsonNode userInfo = doApiCall(userInfoUrl, accessToken);
                    identityNew=ORCIDextractIdentity(userInfo);
                    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, userInfo, getConfig().getAlias());
                }
            }
        }

        if(identityNew){
            identity=identityNew;
        } else {
            identity.setId(id);
            identity.setName(name);
            identity.setEmail(email);
            identity.setBrokerUserId(getConfig().getAlias() + "." + id);
            identity.setUsername(id);
        }

        identity.getContextData().put(VALIDATED_ID_TOKEN, idToken);

        if (tokenResponse != null && tokenResponse.getSessionState() != null) {
            identity.setBrokerSessionId(getConfig().getAlias() + "." + tokenResponse.getSessionState());
        }
        if (tokenResponse != null) identity.getContextData().put(FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse);
        if (tokenResponse != null) processAccessTokenResponse(identity, tokenResponse);
        
        return identity;
    }

    private JsonNode doApiCall(String url, String accessToken) {
        SimpleHttp.Response response = executeRequest(url, SimpleHttp.doGet(url, session).header("Authorization", "Bearer " + accessToken));
        String contentType = response.getFirstHeader(HttpHeaders.CONTENT_TYPE);
        MediaType contentMediaType;
        try {
            contentMediaType = MediaType.valueOf(contentType);
        } catch (IllegalArgumentException ex) {
            contentMediaType = null;
        }
        if (contentMediaType == null || contentMediaType.isWildcardSubtype() || contentMediaType.isWildcardType()) {
            throw new RuntimeException("Unsupported content-type [" + contentType + "] in response from [" + url + "].");
        }
        JsonNode jsonData;

        if (MediaType.APPLICATION_JSON_TYPE.isCompatible(contentMediaType)) {
            jsonData = response.asJson();
        } else if (APPLICATION_JWT_TYPE.isCompatible(contentMediaType)) {
            JWSInput jwsInput;

            try {
                jwsInput = new JWSInput(response.asString());
            } catch (JWSInputException cause) {
                throw new RuntimeException("Failed to parse JWT userinfo response", cause);
            }

            if (verify(jwsInput)) {
                jsonData = JsonSerialization.readValue(jwsInput.getContent(), JsonNode.class);
            } else {
                throw new RuntimeException("Failed to verify signature of userinfo response from [" + url + "].");
            }
        } else {
            throw new RuntimeException("Unsupported content-type [" + contentType + "] in response from [" + url + "].");
        }

        return jsonData;
    }

    @Override
	protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
		String id = getJsonProperty(profile, "id");
		if (id == null) {
			event.detail(Details.REASON, "id claim is null from user info json");
			event.error(Errors.INVALID_TOKEN);
			throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
		}
		return ORCIDExtract(profile);
	}

	private BrokeredIdentityContext ORCIDextractIdentity(JsonNode profile) {
		String id = getJsonProperty(profile, "id");

		BrokeredIdentityContext identity = new BrokeredIdentityContext(id);

		String given_name = getJsonProperty(profile, "given_name");
		String family_name = getJsonProperty(profile, "family_name");

		AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, profile, getConfig().getAlias());

		identity.setId(id);
		identity.setFirstName(given_name);
        identity.setLastName(family_name);
		identity.setBrokerUserId(getConfig().getAlias() + "." + id);
		identity.setUsername(id);

		return identity;
	}
}
