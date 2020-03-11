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

import org.jboss.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
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
import org.keycloak.util.JsonSerialization;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.representations.JsonWebToken;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;

/**
 * @author Marc Schulz-Narres
 */
public class ORCIDIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {
    protected static final Logger logger = Logger.getLogger(ORCIDIdentityProvider.class);

    private static final MediaType APPLICATION_JWT_TYPE = MediaType.valueOf("application/jwt");

    public static final String AUTH_URL = "https://orcid.org/oauth/authorize";
    public static final String TOKEN_URL = "https://orcid.org/oauth/token";
    public static final String PROFILE_URL = "https://orcid.org/oauth/userinfo";
    public static final String EMAIL_URL = "https://api.orcid.org/v2.1";
    public static final String DEFAULT_SCOPE = "openid /read-limited";

    public ORCIDIdentityProvider(KeycloakSession session, ORCIDIdentityProviderConfig config) {
        super(session, config);
		config.setAuthorizationUrl(config.targetSandbox() ? "https://sandbox.orcid.org/oauth/authorize" : AUTH_URL);
		config.setTokenUrl(config.targetSandbox() ? "https://sandbox.orcid.org/oauth/token" : TOKEN_URL);
		config.setUserInfoUrl(config.targetSandbox() ? "https://sandbox.orcid.org/oauth/userinfo" : PROFILE_URL);
        config.setEmailUrl(config.targetSandbox() ? "https://api.sandbox.orcid.org/v2.1" : EMAIL_URL);
        config.setDefaultScope(DEFAULT_SCOPE);
        config.setPrompt("login");
    }

	@Override
	protected String getDefaultScopes() {
		return DEFAULT_SCOPE;
	}

    protected String getEmailUrl() {
        return ((ORCIDIdentityProviderConfig) getConfig()).getEmailUrl();
    }

    private SimpleHttp.Response executeRequest(String url, SimpleHttp request) throws IOException {
        SimpleHttp.Response response = request.asResponse();
        if (response.getStatus() != 200) {
            String msg = "failed to invoke url [" + url + "]";
            try {
                String tmp = response.asString();
                if (tmp != null) msg = tmp;

            } catch (IOException e) {

            }
            throw new IdentityBrokerException("Failed to invoke url [" + url + "]: " + msg);
        }
        return  response;
    }

    @Override
    protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken, JsonWebToken idToken) throws IOException {
        String id = idToken.getSubject();
        BrokeredIdentityContext identity = new BrokeredIdentityContext(id);
        BrokeredIdentityContext identityNew = null;
        String name = (String) idToken.getOtherClaims().get(IDToken.NAME);
        String preferredUsername = (String) idToken.getOtherClaims().get(getusernameClaimNameForIdToken());
        String email = (String) idToken.getOtherClaims().get(IDToken.EMAIL);

        if (!getConfig().isDisableUserInfoService()) {
            String userInfoUrl = getUserInfoUrl();
            String emailInfoUrl = getEmailUrl();
            if (userInfoUrl != null && !userInfoUrl.isEmpty() && emailInfoUrl != null && !emailInfoUrl.isEmpty() && (id == null || name == null || preferredUsername == null || email == null)) {
                if (accessToken != null) {
                    JsonNode userInfo = doApiCall(userInfoUrl, accessToken);
                    identityNew=ORCIDextractIdentity(userInfo);

                    String userEmailEndpointUrl = emailInfoUrl + "/" + identityNew.getId() + "/email";
                    JsonNode emailInfo = doApiCall(userEmailEndpointUrl, accessToken);

                    email = emailInfo.at("/email/0/email").asText();
                    identityNew.setEmail(email);

                    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, userInfo, getConfig().getAlias());
                }
            }
        }

        if(identityNew != null){
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

    private JsonNode doApiCall(String url, String accessToken) throws IOException {
        SimpleHttp.Response response = executeRequest(url, SimpleHttp.doGet(url, session).header("Authorization", "Bearer " + accessToken).header("Accept", "application/json"));
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
		String id = getJsonProperty(profile, "sub");
		if (id == null) {
			event.detail(Details.REASON, "id claim is null from user info json");
			event.error(Errors.INVALID_TOKEN);
			throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
		}
		return ORCIDextractIdentity(profile);
	}

	private BrokeredIdentityContext ORCIDextractIdentity(JsonNode profile) {
		String id = getJsonProperty(profile, "sub");

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
