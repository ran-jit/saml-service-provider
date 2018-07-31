package service.provider.tenant.identifier;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import service.provider.constants.SamlConstants.BeanConstants;
import service.provider.exception.TenantNotExistsException;
import service.provider.manager.MetadataManager;
import service.provider.model.TenantInfo;
import service.provider.util.URLUtil;

import javax.annotation.PreDestroy;
import javax.servlet.http.HttpServletRequest;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public abstract class TenantIdentifier {

    @Autowired
    @Qualifier(value = BeanConstants.METADATA)
    protected MetadataManager metadataManager;

    @Autowired
    protected URLUtil urlUtil;

    protected final String entityBaseUrl;
    protected final String loginProcessingUrl;
    protected final String logoutProcessingUrl;

    protected final String loginFilterProcessingUrl;
    protected final String logoutFilterProcessingUrl;
    protected final String metadataProcessingUrl;

    @Getter
    @AllArgsConstructor
    public enum TenantCode {
        DNS("D_1001"), ATTRIBUTE("A_1002"), URL("U_1003");
        private String errorCode;
    }

    public TenantIdentifier(String entityBaseUrl, String loginProcessingUrl, String logoutProcessingUrl,
                            String loginFilterProcessingUrl, String logoutFilterProcessingUrl, String metadataProcessingUrl) {
        this.entityBaseUrl = entityBaseUrl;
        this.loginProcessingUrl = loginProcessingUrl;
        this.logoutProcessingUrl = logoutProcessingUrl;
        this.loginFilterProcessingUrl = loginFilterProcessingUrl;
        this.logoutFilterProcessingUrl = logoutFilterProcessingUrl;
        this.metadataProcessingUrl = metadataProcessingUrl;
    }

    protected TenantInfo identifyTenant(HttpServletRequest request, String tenantId, TenantCode errorCode) throws TenantNotExistsException {
        TenantInfo tenantInfo = this.metadataManager.getTenantInfo(tenantId);
        if (tenantInfo == null) {
            throw new TenantNotExistsException(getErrorIdentifier(request), errorCode);
        }
        return tenantInfo;
    }

    public abstract TenantInfo identifyTenant(HttpServletRequest request) throws TenantNotExistsException;

    protected abstract String getTenantId(HttpServletRequest request);

    public abstract void updateMetadata(TenantInfo tenantInfo, String remoteEntityId);

    protected abstract String getErrorIdentifier(HttpServletRequest request);

    public TenantInfo getTenantMetadata(HttpServletRequest request) {
        String tenantId = getTenantId(request);
        return metadataManager.getTenantInfo(tenantId);
    }

    @PreDestroy
    public void destroy() {
        this.urlUtil = null;
        this.metadataManager = null;
    }

}
