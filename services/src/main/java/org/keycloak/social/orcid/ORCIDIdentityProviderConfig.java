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

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * @author Marc Schulz-Narres
 */
public class ORCIDIdentityProviderConfig extends OIDCIdentityProviderConfig {

    public ORCIDIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public boolean targetSandbox() {
        String sandbox = getConfig().get("sandbox");
        //return sandbox == null ? false : Boolean.valueOf(sandbox);
        return true;
    }

    public void setSandbox(boolean sandbox) {
        getConfig().put("sandbox", String.valueOf(sandbox));
    }

    public String getEmailUrl() {
        return getConfig().get("emailurl");
    }

    public void setEmailUrl(String emailurl) {
        getConfig().put("emailurl", String.valueOf(emailurl));
    }

}
