package service.provider.util;

import com.google.common.collect.Maps;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.util.resource.ClasspathResource;
import org.opensaml.util.resource.FilesystemResource;
import org.opensaml.util.resource.HttpResource;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import service.provider.config.MetadataConfig;
import service.provider.model.TenantInfo;

import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.stream.Collectors;

/**
 * author: Ranjith Manickam @ 2 August' 2018
 */
public class MetadataUtil {

    private final StaticBasicParserPool parserPool;

    private static final Log LOGGER = LogFactory.getLog(MetadataUtil.class);

    public MetadataUtil(StaticBasicParserPool parserPool) {
        this.parserPool = parserPool;
    }

    public List<MetadataProvider> getProviders(MetadataConfig metadataConfig) {
        if (CollectionUtils.isNotEmpty(metadataConfig.getIdp())) {
            return metadataConfig.getIdp().stream()
                    .map(tenantInfo -> {
                        try {
                            return idpMetadata(tenantInfo);
                        } catch (Exception ex) {
                            LOGGER.error("Error in metadata generation, metadataConfig: " + metadataConfig, ex);
                        }
                        return null;
                    }).collect(Collectors.toList());
        }
        return null;
    }

    private ExtendedMetadataDelegate idpMetadata(TenantInfo tenantInfo) throws MetadataProviderException, ResourceException {
        Resource resource;
        switch (tenantInfo.getMetadata().getType()) {
            case FILE:
                resource = new FilesystemResource(tenantInfo.getMetadata().getFilePath());
                break;
            case URL:
                resource = new HttpResource(tenantInfo.getMetadata().getFilePath());
                break;
            default:
                resource = new ClasspathResource(tenantInfo.getMetadata().getFilePath());
                break;
        }

        ResourceBackedMetadataProvider metadataProvider = new ResourceBackedMetadataProvider(new Timer(true), resource);
        metadataProvider.setParserPool(this.parserPool);

        ExtendedMetadata defaultMetadata = new ExtendedMetadata();
        defaultMetadata.setAlias(tenantInfo.getTenantId());

        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setAlias(tenantInfo.getTenantId());
        extendedMetadata.setLocal(true);
        extendedMetadata.setSignMetadata(false);
        extendedMetadata.setIdpDiscoveryEnabled(false);

        Map<String, ExtendedMetadata> metadataMap = Maps.newHashMap();
        metadataMap.put(tenantInfo.getTenantId(), extendedMetadata);

        ExtendedMetadataDelegate metadataDelegate = new ExtendedMetadataDelegate(metadataProvider, defaultMetadata, metadataMap);
        metadataDelegate.setMetadataTrustCheck(tenantInfo.getMetadata().getTrustCheck());
        metadataDelegate.setMetadataRequireSignature(false);
        return metadataDelegate;
    }

}
