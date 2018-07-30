package service.provider.filter;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.stereotype.Component;
import service.provider.constants.SamlConstants.UrlConstants;
import service.provider.constants.SamlConstants.ValueConstants;
import service.provider.exception.TenantNotExistsException;
import service.provider.manager.MetadataManager;
import service.provider.model.TenantInfo;
import service.provider.util.URLUtil;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityFilter implements Filter {

    private final String homePageUrl;
    private final String errorPageUrl;
    private final String instanceHost;
    private final String loginProcessingUrl;
    private final String logoutProcessingUrl;

    private final URLUtil urlUtil;
    private final MetadataManager metadataManager;

    private static final Log LOGGER = LogFactory.getLog(SecurityFilter.class);

    @Autowired
    public SecurityFilter(@Value(value = ValueConstants.HOME_PAGE_URL) String homePageUrl,
                          @Value(value = ValueConstants.ERROR_PAGE_URL) String errorPageUrl,
                          @Value(value = ValueConstants.ENTITY_BASE_URL) String entityBaseUrl,
                          @Value(value = ValueConstants.LOGIN_PROCESSING_URL) String loginProcessingUrl,
                          @Value(value = ValueConstants.LOGOUT_PROCESSING_URL) String logoutProcessingUrl,
                          URLUtil urlUtil,
                          MetadataManager metadataManager) {
        this.homePageUrl = homePageUrl;
        this.errorPageUrl = errorPageUrl;
        this.loginProcessingUrl = loginProcessingUrl;
        this.logoutProcessingUrl = logoutProcessingUrl;
        this.urlUtil = urlUtil;
        this.metadataManager = metadataManager;

        try {
            this.instanceHost = this.urlUtil.getDomainName(entityBaseUrl);
        } catch (MalformedURLException ex) {
            throw new RuntimeException(String.format("Error in entity base url, url: %s", entityBaseUrl), ex);
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        if (this.instanceHost.equals(this.urlUtil.getDomainName(((HttpServletRequest) request).getRequestURL().toString()))) {
            String idpEntityId = request.getParameter(SAMLEntryPoint.IDP_PARAMETER);
            if (StringUtils.isEmpty(idpEntityId)) {
                // internal redirection
                TenantInfo tenantInfo;
                try {
                    tenantInfo = this.metadataManager.getTenantIdentifier().identifyTenant((HttpServletRequest) request);
                } catch (TenantNotExistsException ex) {
                    sendRedirect(response, this.errorPageUrl, ex.getMessage());
                    return;
                }

                String requestUri = ((HttpServletRequest) request).getRequestURI();
                if (this.loginProcessingUrl.equals(requestUri)) {
                    internalRedirect(response, requestUri, tenantInfo.getLoginProcessingUrl());
                    return;
                } else if (this.logoutProcessingUrl.equals(requestUri)) {
                    internalRedirect(response, requestUri, tenantInfo.getLogoutProcessingUrl());
                    return;
                }
            } else if (!idpExists(idpEntityId)) {
                // idp doesn't exists
                LOGGER.error(String.format("Invalid IdP entityId, %s", idpEntityId));
                sendRedirect(response, this.errorPageUrl);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }

    private boolean idpExists(String idpEntityId) {
        return this.metadataManager.getIDPEntityNames().contains(idpEntityId);
    }

    private void internalRedirect(ServletResponse response, String requestUri, String url) throws IOException {
        try {
            sendRedirect(response, url);
        } catch (Exception ex) {
            LOGGER.error(String.format("Error in internal redirection, URL: %s ### message: %s", url, ex.getMessage()));
            if (requestUri.startsWith(this.loginProcessingUrl)) {
                sendRedirect(response, this.errorPageUrl);
            } else {
                sendRedirect(response, this.homePageUrl);
            }
        }
    }

    private void sendRedirect(ServletResponse response, String url) throws IOException {
        ((HttpServletResponse) response).sendRedirect(url);
    }

    private void sendRedirect(ServletResponse response, String url, String errorMessage) throws IOException {
        ((HttpServletResponse) response).sendRedirect(String.format("%s?%s=%s", url, UrlConstants.MESSAGE_PARAM, errorMessage));
    }

}
