package org.wso2.sample.identity.oauth2.grant.passwor; /**
 * Created by isuri on 12/5/17.
 */
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.balana.ParsingException;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.pdp.EntitlementEngine;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.List;

/**
 *  Modified version of default passwor grant type
 */
public class RoleBasedPasswordGrant extends PasswordGrantHandler {

    private static Log log = LogFactory.getLog(RoleBasedPasswordGrant.class);


    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        //  default passwor validation
        boolean superAuthorized = super.validateGrant(tokReqMsgCtx);

        //  default passwor validation

        boolean authorized = super.authorizeAccessDelegation(tokReqMsgCtx);

        // additional check for role based
        if (authorized && superAuthorized) {

            String username = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getResourceOwnerUsername();

            try {
                String[] roles = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager()
                        .getRoleListOfUser
                                (MultitenantUtils.getTenantAwareUsername(username));

                for (String role : getAuthorizedRoles()) {
                    if ((new ArrayList<>(java.util.Arrays.asList(roles))).contains(role)) {
                        return true;
                    }
                }

            } catch (UserStoreException e) {
                log.error(e);
            }
        }

        return false;
    }


    /**
     * Retrieve authorized roles.  This can be read from configuration file.
     *
     * @return
     */
    public String getAuthorizedRoles(String request) throws EntitlementException, ParsingException {

        String roles = null;
        try {
            EntitlementEngine entitlementEngine = EntitlementEngine.getInstance();
            roles = entitlementEngine.evaluate(request);


        } catch (EntitlementException e) {


        }
        return roles;
    }
    private List<String> getAuthorizedRoles() {

        List<String> roles = new ArrayList<String>();

        // JUST FOR TESTING
        roles.add("finance");
        return roles;

    }
}