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
/*
    @Override
    protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken, JsonWebToken idToken) throws IOException {

    }

    private BrokeredIdentityContext ORCIDextractIdentity(JsonNode profile) {

    }
*/
    @Override
	protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
		String id = getJsonProperty(profile, "id");
		if (id == null) {
			event.detail(Details.REASON, "id claim is null from user info json");
			event.error(Errors.INVALID_TOKEN);
			throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
		}
		return ORCIDExtractFromProfile(profile);
	}

	private BrokeredIdentityContext ORCIDextractIdentityFromProfile(JsonNode profile) {
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
