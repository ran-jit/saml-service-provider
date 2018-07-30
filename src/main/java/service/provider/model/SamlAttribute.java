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
public class SamlAttribute implements Serializable {
    private static final long serialVersionUID = -650444051215033238L;

    private final String name;
    private final String value;
    private final List<String> values;

}
