package service.provider.filter;

import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import service.provider.constants.SamlConstants.MetadataConstants;
import service.provider.manager.MetadataManager;
import service.provider.model.TenantInfo;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class SamlMetadataDisplayFilter extends MetadataDisplayFilter {

    @Override
    protected void processMetadataDisplay(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        try {
            TenantInfo tenantInfo = ((MetadataManager) manager).getTenantIdentifier().identifyTenant(request);

            SAMLMessageContext context = this.contextProvider.getLocalEntity(request, response);
            response.setContentType(MetadataConstants.CONTENT_TYPE);
            response.addHeader(HttpHeaders.CONTENT_DISPOSITION, tenantInfo.getMetadata().getFileName());
            displayMetadata(context.getLocalEntityId(), response.getWriter());
        } catch (MetadataProviderException ex) {
            throw new ServletException("Error initializing metadata", ex);
        }
    }

}
