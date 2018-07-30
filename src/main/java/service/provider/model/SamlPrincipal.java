package service.provider.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;
import java.util.List;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
@Getter
@Builder
@ToString
@JsonInclude(Include.NON_NULL)
public class SamlPrincipal implements Serializable {
    private static final long serialVersionUID = -1580209199067591088L;

    private String nameID;
    private String nameIDType;
    private TenantInfo tenantInfo;
    private final List<SamlAttribute> attributes;

}
