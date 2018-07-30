package service.provider.model;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.annotation.Nonnull;
import java.io.Serializable;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
@Getter
@Setter
@ToString
@EqualsAndHashCode(of = {"tenantId"})
public class TenantInfo implements Serializable {
    private static final long serialVersionUID = -7407833912680084581L;

    @Nonnull
    private String tenantId;
    private Metadata metadata = new Metadata();

    private String entityBaseUrl;
    private String loginProcessingUrl;
    private String logoutProcessingUrl;
    private String metadataProcessingUrl;
    private String loginFilterProcessingUrl;
    private String logoutFilterProcessingUrl;

}
