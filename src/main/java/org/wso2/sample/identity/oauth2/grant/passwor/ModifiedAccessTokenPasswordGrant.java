package org.wso2.sample.identity.oauth2.grant.passwor; /**
 * Created by isuri on 12/5/17.
 */

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.UUID;
public class ModifiedAccessTokenPasswordGrant extends PasswordGrantHandler {

    private static Log log = LogFactory.getLog(ModifiedAccessTokenPasswordGrant.class);

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        // calling super
        OAuth2AccessTokenRespDTO tokenRespDTO =  super.issue(tokReqMsgCtx);

        // set modified access token
        tokenRespDTO.setAccessToken(generateAccessToken(tokReqMsgCtx.getAuthorizedUser().toString()));

        return tokenRespDTO;

    }


    /**
     * Demo sample for generating custom access token
     *
     * @param userName
     * @return
     */
    private String generateAccessToken(String userName){

        String token = UUID.randomUUID().toString();

        // retrieve user's email address and append it to access token
        userName = MultitenantUtils.getTenantAwareUsername(userName);
        String email = null;

        try {
            email = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager()
                    .getUserClaimValue(userName, "http://wso2.org/claims/emailaddress", null);
        } catch (UserStoreException e) {
            log.error(e);
        }

        if(email != null){
            token = token + ":" + email;
        }

        return token;
    }
}
