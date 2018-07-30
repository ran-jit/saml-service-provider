package service.provider.filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import service.provider.constants.SamlConstants.BeanConstants;
import service.provider.constants.SamlConstants.UrlConstants;
import service.provider.exception.TenantNotExistsException;
import service.provider.manager.MetadataManager;
import service.provider.model.TenantInfo;

import javax.annotation.PreDestroy;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class SamlLogoutFilter extends SAMLLogoutFilter {

    private final String homePageUrl;
    private final String errorPageUrl;

    @Autowired
    @Qualifier(value = BeanConstants.METADATA)
    private MetadataManager metadataManager;

    private static final Log LOGGER = LogFactory.getLog(SamlLogoutFilter.class);

    public SamlLogoutFilter(String homePageUrl, String errorPageUrl, LogoutSuccessHandler successHandler, LogoutHandler localHandler, LogoutHandler globalHandlers) {
        super(successHandler, new LogoutHandler[]{localHandler}, new LogoutHandler[]{globalHandlers});
        this.homePageUrl = homePageUrl;
        this.errorPageUrl = errorPageUrl;
    }

    @Override
    public void processLogout(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (requiresLogout(request, response)) {
            try {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                TenantInfo tenantInfo = this.metadataManager.getTenantIdentifier().identifyTenant(request);

                if (authentication == null || !(authentication.getCredentials() instanceof SAMLCredential)) {
                    LOGGER.info("Authentication details not exists. So, redirecting to home page..");
                    response.sendRedirect((tenantInfo == null || tenantInfo.getLoginProcessingUrl() == null) ? this.homePageUrl : tenantInfo.getLoginProcessingUrl());
                    return;
                }

                // Terminate the session first
                for (LogoutHandler handler : super.globalHandlers) {
                    handler.logout(request, response, authentication);
                }

                // Notify session participants using SAML Single Logout profile
                SAMLCredential credential = (SAMLCredential) authentication.getCredentials();
                request.setAttribute(SAMLConstants.LOCAL_ENTITY_ID, credential.getLocalEntityID());
                request.setAttribute(SAMLConstants.PEER_ENTITY_ID, credential.getRemoteEntityID());

                SAMLMessageContext context = super.contextProvider.getLocalAndPeerEntity(request, response);
                profile.sendLogoutRequest(context, credential);
                samlLogger.log(SAMLConstants.LOGOUT_REQUEST, SAMLConstants.SUCCESS, context);

            } catch (SAMLException ex) {
                LOGGER.debug("Error initializing global logout", ex);
                throw new ServletException("Error initializing global logout", ex);
            } catch (MetadataProviderException ex) {
                LOGGER.debug("Error processing metadata", ex);
                throw new ServletException("Error processing metadata", ex);
            } catch (MessageEncodingException ex) {
                LOGGER.debug("Error encoding outgoing message", ex);
                throw new ServletException("Error encoding outgoing message", ex);
            } catch (TenantNotExistsException ex) {
                response.sendRedirect(String.format("%s?%s=%s", this.errorPageUrl, UrlConstants.MESSAGE_PARAM, ex.getMessage()));
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    @PreDestroy
    public void destroy() {
        this.metadataManager = null;
    }

}
