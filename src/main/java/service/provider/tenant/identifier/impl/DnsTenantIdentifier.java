package service.provider.tenant.identifier.impl;

import org.springframework.security.saml.SAMLEntryPoint;
import service.provider.constants.SamlConstants.MetadataConstants;
import service.provider.exception.TenantNotExistsException;
import service.provider.model.TenantInfo;
import service.provider.tenant.identifier.TenantIdentifier;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class DnsTenantIdentifier extends TenantIdentifier {

    public DnsTenantIdentifier(String entityBaseUrl, String loginProcessingUrl, String logoutProcessingUrl,
                               String loginFilterProcessingUrl, String logoutFilterProcessingUrl, String metadataProcessingUrl) {
        super(entityBaseUrl, loginProcessingUrl, logoutProcessingUrl, loginFilterProcessingUrl, logoutFilterProcessingUrl, metadataProcessingUrl);
    }

    @Override
    public TenantInfo identifyTenant(HttpServletRequest request) throws TenantNotExistsException {
        String tenantId = getTenantId(request);
        return super.identifyTenant(request, tenantId, TenantCode.DNS);
    }

    @Override
    protected String getTenantId(HttpServletRequest request) {
        String serverName = request.getServerName();
        return serverName.split("\\.")[0];
    }

    @Override
    public void updateMetadata(@Nonnull TenantInfo tenantInfo, @Nonnull String remoteEntityId) {
        try {
            URL url = new URL(super.entityBaseUrl);
            String domain = super.urlUtil.getDomainName(url);

            tenantInfo.getMetadata().setRemoteEntityId(remoteEntityId);
            tenantInfo.getMetadata().setLocalEntityId(String.format("%s.%s", tenantInfo.getTenantId(), domain));
            tenantInfo.getMetadata().setFileName(String.format(MetadataConstants.FILE_NAME, tenantInfo.getTenantId()));

            String entityBaseUrl = String.format("%s://%s.%s", url.getProtocol(), tenantInfo.getTenantId(), domain);
            if (url.getPort() > 0) {
                entityBaseUrl = String.format("%s:%d", entityBaseUrl, url.getPort());
            }
            tenantInfo.setEntityBaseUrl(entityBaseUrl);
            tenantInfo.setLoginProcessingUrl(String.format("%s%s?%s=%s", entityBaseUrl, super.loginProcessingUrl, SAMLEntryPoint.IDP_PARAMETER, remoteEntityId));
            tenantInfo.setLogoutProcessingUrl(String.format("%s%s?%s=%s", entityBaseUrl, super.logoutProcessingUrl, SAMLEntryPoint.IDP_PARAMETER, remoteEntityId));

            tenantInfo.setLoginFilterProcessingUrl(super.loginFilterProcessingUrl);
            tenantInfo.setLogoutFilterProcessingUrl(super.logoutFilterProcessingUrl);
            tenantInfo.setMetadataProcessingUrl(super.metadataProcessingUrl);
        } catch (MalformedURLException ex) {
            throw new RuntimeException("Error updating metadata", ex);
        }
    }

    @Override
    protected String getErrorIdentifier(HttpServletRequest request) {
        return request.getServerName();
    }

}
