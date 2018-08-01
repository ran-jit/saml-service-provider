package service.provider.manager;

import com.google.common.collect.Maps;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataProvider;
import service.provider.config.MetadataConfig;
import service.provider.model.TenantInfo;
import service.provider.tenant.identifier.TenantIdentifier;
import service.provider.util.MetadataUtil;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class MetadataManager extends CachingMetadataManager {

    @Autowired
    protected TenantIdentifier tenantIdentifier;

    @Autowired
    protected MetadataUtil metadataUtil;

    private final MetadataConfig metadataConfig;
    private final Map<String, TenantInfo> metadataCache;

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private static final Log LOGGER = LogFactory.getLog(MetadataManager.class);

    public MetadataManager(MetadataConfig metadataConfig, List<MetadataProvider> providers) throws MetadataProviderException {
        super(providers);
        this.metadataConfig = metadataConfig;
        this.metadataCache = Maps.newHashMap();
    }

    @PostConstruct
    public void init() {
        this.metadataConfig.getIdp().forEach(tenantInfo -> {
            try {
                super.refreshMetadata();
                this.lock.readLock().lock();
                String entityId = getIDPEntityNames().stream()
                        .filter(idpEntityName -> (validate(idpEntityName, tenantInfo.getTenantId()) != null))
                        .collect(Collectors.joining());

                if (StringUtils.isNotEmpty(entityId)) {
                    this.tenantIdentifier.updateMetadata(tenantInfo, entityId);
                    this.metadataCache.put(tenantInfo.getTenantId(), tenantInfo);
                    this.metadataCache.put(tenantInfo.getMetadata().getLocalEntityId(), tenantInfo);
                }
            } finally {
                this.lock.readLock().unlock();
            }
        });
    }

    public TenantInfo getTenantInfo(String key) {
        return this.metadataCache.get(key);
    }

    private String validate(String entityId, String alias) {
        for (MetadataProvider provider : getProviders()) {
            if (provider instanceof ExtendedMetadataProvider) {
                try {
                    ExtendedMetadataProvider extendedProvider = (ExtendedMetadataProvider) provider;
                    ExtendedMetadata extendedMetadata = extendedProvider.getExtendedMetadata(entityId);
                    if (extendedMetadata != null && alias.equals(extendedMetadata.getAlias())) {
                        return entityId;
                    }
                } catch (MetadataProviderException ex) {
                    LOGGER.error(String.format("Error retrieving extended metadata, entityId: %s :: alias: %s :: message: %s", entityId, alias, ex.getMessage()));
                }
            }
        }
        return null;
    }

    public TenantIdentifier getTenantIdentifier() {
        return this.tenantIdentifier;
    }

    @PreDestroy
    public void destroy() {
        this.tenantIdentifier = null;
    }

}
