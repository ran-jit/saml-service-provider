package service.provider.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import service.provider.constants.SamlConstants.BeanConstants;
import service.provider.manager.MetadataManager;
import service.provider.model.TenantInfo;

import javax.annotation.PreDestroy;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class LogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    @Autowired
    @Qualifier(value = BeanConstants.METADATA)
    private MetadataManager metadataManager;

    private static final Log LOGGER = LogFactory.getLog(LogoutSuccessHandler.class);

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        TenantInfo tenantInfo = this.metadataManager.getTenantIdentifier().identifyTenant(request);
        if (tenantInfo == null || tenantInfo.getLogoutProcessingUrl() == null) {
            LOGGER.info("metadata is null, so redirecting to default target url");
            return getDefaultTargetUrl();
        }
        return tenantInfo.getLogoutProcessingUrl();
    }

    @PreDestroy
    public void destroy() {
        this.metadataManager = null;
    }

}
