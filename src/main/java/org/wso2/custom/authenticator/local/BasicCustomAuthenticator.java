package org.wso2.custom.authenticator.local;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.custom.authenticator.local.internal.BasicCustomAuthenticatorServiceComponent;
import org.wso2.custom.authenticator.local.utils.DbUtils;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
 

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
 
/**
* Username Password based custom Authenticator
*/
public class BasicCustomAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {
 
   private static final long serialVersionUID = 4345354156955223654L;
   private static final Log log = LogFactory.getLog(BasicCustomAuthenticator.class);
   boolean result = false;
 
 
   @Override
   protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                HttpServletResponse response,
                                                AuthenticationContext context)
           throws AuthenticationFailedException {
 
       String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();//This is the
       // default WSO2 IS login page. If you can create your custom login page you can use
       // that instead.
       String queryParams =
               FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                       context.getCallerSessionKey(),
                       context.getContextIdentifier());
 
       try {
           String retryParam = "";
 
           if (context.isRetrying()) {
               retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
           }
 
           response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) +
                   "&authenticators=BasicAuthenticator:" + "LOCAL" + retryParam);
       } catch (IOException e) {
           throw new AuthenticationFailedException(e.getMessage(), e);
       }
   }
 
   /**
    * This method is used to process the authentication response.
    * Inside here we check if this is a authentication request coming from oidc flow and then check if the user is
    * in the 'photoSharingRole'.
    */
   @Override
   protected void processAuthenticationResponse(HttpServletRequest request,
                                                HttpServletResponse response, AuthenticationContext context)
           throws AuthenticationFailedException {
 
       String username = request.getParameter(BasicCustomAuthenticatorConstants.MSISDN);
       boolean isAuthenticated = true;
       context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
       boolean authorization = false;
 
       if(isAuthenticated) {
           if ("oidc".equalsIgnoreCase(context.getRequestType())) {
               // authorization only for openid connect requests
               try {
                   int tenantId = BasicCustomAuthenticatorServiceComponent.getRealmService().getTenantManager().
                           getTenantId(MultitenantUtils.getTenantDomain(username));
                   UserStoreManager userStoreManager = (UserStoreManager) BasicCustomAuthenticatorServiceComponent.getRealmService().
                           getTenantUserRealm(tenantId).getUserStoreManager();
 
                   authorization = response(username);
                
               } catch (UserStoreException e) {
                   log.error(e);
               } catch (org.wso2.carbon.user.api.UserStoreException e) {
                   log.error(e);
               }
           } else {
               // others scenarios are not verified.
               authorization = false;
           }
 
           if (!authorization) {
               log.error("user authorization is failed.");
 
               throw new InvalidCredentialsException("User authentication failed due to invalid credentials");
 
           }
       }
   }
 
   @Override
   protected boolean retryAuthenticationEnabled() {
       return false;
   }
 
   @Override
   public String getFriendlyName() {
       //Set the name to be displayed in local authenticator drop down lsit
       return BasicCustomAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
   }
 
   @Override
   public boolean canHandle(HttpServletRequest httpServletRequest) {
       String msisdn = httpServletRequest.getParameter(BasicCustomAuthenticatorConstants.MSISDN);
       if (msisdn != null) {
           return true;
       }
       return false;
   }
   public boolean response(String msisdn) throws AuthenticationFailedException {
       
       return DbUtils.insertSMSPIN(msisdn);
   }
 
   @Override
   public String getContextIdentifier(HttpServletRequest httpServletRequest) {
       return httpServletRequest.getParameter("sessionDataKey");
   }
 
   @Override
   public String getName() {
       return BasicCustomAuthenticatorConstants.AUTHENTICATOR_NAME;
   }
}