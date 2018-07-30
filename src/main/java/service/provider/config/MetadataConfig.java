package service.provider.config;

import com.google.common.collect.Lists;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import service.provider.model.TenantInfo;

import java.io.Serializable;
import java.util.List;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
@Getter
@Setter
@ToString
@Component
@ConfigurationProperties(prefix = "saml")
@EnableConfigurationProperties
public class MetadataConfig implements Serializable {
    private static final long serialVersionUID = 94760534339951317L;
    private List<TenantInfo> idp = Lists.newArrayList();
}
