package service.provider.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import service.provider.constants.SamlConstants.MetadataResourceType;

import javax.annotation.Nonnull;
import java.io.Serializable;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
@Getter
@Setter
@ToString
public class Metadata implements Serializable {
    private static final long serialVersionUID = 2365645146819597597L;

    private String localEntityId;
    private String remoteEntityId;

    private String fileName;

    @Nonnull
    private String filePath;

    @Nonnull
    private Boolean trustCheck;

    @Nonnull
    private MetadataResourceType type;

}
