package service.provider.filter;

import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import service.provider.manager.MetadataManager;
import service.provider.model.TenantInfo;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class SamlMetadataGeneratorFilter extends MetadataGeneratorFilter {

    public SamlMetadataGeneratorFilter(MetadataGenerator generator) {
        super(generator);
    }

    @Override
    protected void processMetadataInitialization(HttpServletRequest request) throws ServletException {
        if (super.manager.getHostedSPName() == null || !super.manager.getHostedSPName().equals(request.getServerName())) {
            synchronized (SamlMetadataGeneratorFilter.class) {

                TenantInfo tenantInfo = ((MetadataManager) super.manager).getTenantIdentifier().getTenantMetadata(request);
                super.generator.setEntityId(tenantInfo.getMetadata().getLocalEntityId());
                super.generator.setEntityBaseURL(tenantInfo.getEntityBaseUrl());

                super.manager.setHostedSPName(null);
                super.generator.setId(null);
                super.processMetadataInitialization(request);
            }
        }
    }

}
