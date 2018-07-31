package service.provider.tenant.identifier.impl;

import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.util.StringUtils;
import service.provider.constants.SamlConstants.MetadataConstants;
import service.provider.exception.TenantNotExistsException;
import service.provider.model.TenantInfo;
import service.provider.tenant.identifier.TenantIdentifier;

import javax.servlet.http.HttpServletRequest;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class AttributeTenantIdentifier extends TenantIdentifier {

    private final String param;

    public AttributeTenantIdentifier(String entityBaseUrl, String loginProcessingUrl, String logoutProcessingUrl,
                                     String loginFilterProcessingUrl, String logoutFilterProcessingUrl, String metadataProcessingUrl, String param) {
        super(entityBaseUrl, loginProcessingUrl, logoutProcessingUrl, loginFilterProcessingUrl, logoutFilterProcessingUrl, metadataProcessingUrl);
        this.param = param;
    }

    @Override
    public TenantInfo identifyTenant(HttpServletRequest request) throws TenantNotExistsException {
        String tenantId = getTenantId(request);
        return super.identifyTenant(request, tenantId, TenantCode.ATTRIBUTE);
    }

    @Override
    protected String getTenantId(HttpServletRequest request) {
        String tenantId = request.getParameter(this.param);
        return (StringUtils.isEmpty(tenantId)) ? (String) request.getAttribute(this.param) : null;
    }

    @Override
    public void updateMetadata(TenantInfo tenantInfo, String remoteEntityId) {
        tenantInfo.setEntityBaseUrl(super.entityBaseUrl);
        tenantInfo.getMetadata().setFileName(String.format(MetadataConstants.FILE_NAME, tenantInfo.getTenantId()));

        tenantInfo.getMetadata().setRemoteEntityId(remoteEntityId);
        tenantInfo.getMetadata().setLocalEntityId(String.format("%s?%s=%s", super.entityBaseUrl, this.param, tenantInfo.getTenantId()));

        tenantInfo.setLoginProcessingUrl(String.format("%s%s?%s=%s&%s=%s", super.entityBaseUrl, super.loginProcessingUrl, this.param, tenantInfo.getTenantId(), SAMLEntryPoint.IDP_PARAMETER, remoteEntityId));
        tenantInfo.setLogoutProcessingUrl(String.format("%s%s?%s=%s&%s=%s", super.entityBaseUrl, super.logoutProcessingUrl, this.param, tenantInfo.getTenantId(), SAMLEntryPoint.IDP_PARAMETER, remoteEntityId));

        tenantInfo.setLoginFilterProcessingUrl(String.format("%s?%s=%s", super.loginFilterProcessingUrl, this.param, tenantInfo.getTenantId()));
        tenantInfo.setLogoutFilterProcessingUrl(String.format("%s?%s=%s", super.logoutFilterProcessingUrl, this.param, tenantInfo.getTenantId()));
        tenantInfo.setMetadataProcessingUrl(String.format("%s?%s=%s", super.metadataProcessingUrl, this.param, tenantInfo.getTenantId()));
    }

    @Override
    protected String getErrorIdentifier(HttpServletRequest request) {
        return String.format("%s?%s=%s", super.entityBaseUrl, this.param, request.getParameter(this.param));
    }

}
