package service.provider.service;

import org.apache.commons.collections.CollectionUtils;
import org.opensaml.saml2.core.NameID;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.util.StringUtils;
import service.provider.constants.SamlConstants;
import service.provider.manager.MetadataManager;
import service.provider.model.SamlAttribute;
import service.provider.model.SamlPrincipal;

import javax.annotation.PreDestroy;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class SamlUserDetailsService implements SAMLUserDetailsService {

    @Autowired
    @Qualifier(value = SamlConstants.BeanConstants.METADATA)
    private MetadataManager metadataManager;

    @Override
    public Object loadUserBySAML(SAMLCredential samlCredential) throws UsernameNotFoundException {
        List<SamlAttribute> attributes = samlCredential.getAttributes().stream().map(attribute -> {
            List<String> values = attribute.getAttributeValues().stream()
                    .map(SamlUserDetailsService::getStringValueFromXMLObject)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .collect(Collectors.toList());

            return SamlAttribute.builder()
                    .name(attribute.getName())
                    .values((CollectionUtils.isNotEmpty(values) && values.size() > 1) ? values : null)
                    .value((CollectionUtils.isNotEmpty(values) && values.size() == 1) ? values.get(0) : null)
                    .build();
        }).collect(Collectors.toList());

        NameID nameID = samlCredential.getNameID();
        return SamlPrincipal.builder()
                .nameID(nameID.getValue())
                .nameIDType(nameID.getFormat())
                .attributes(attributes)
                .tenantInfo(this.metadataManager.getTenantInfo(samlCredential.getLocalEntityID()))
                .build();
    }

    private static Optional<String> getStringValueFromXMLObject(XMLObject xmlObject) {
        if (xmlObject instanceof XSString) {
            return Optional.of(((XSString) xmlObject).getValue());
        } else if (xmlObject instanceof XSAny) {
            XSAny xsAny = (XSAny) xmlObject;
            String textContent = xsAny.getTextContent();
            if (StringUtils.hasText(textContent)) {
                return Optional.of(textContent);
            }

            List<XMLObject> unknownXMLObjects = xsAny.getUnknownXMLObjects();
            if (!CollectionUtils.isEmpty(unknownXMLObjects)) {
                XMLObject xmlObj = unknownXMLObjects.get(0);
                if (xmlObj instanceof NameID) {
                    NameID nameID = (NameID) xmlObj;
                    return Optional.of(nameID.getValue());
                }
            }
        }
        return Optional.empty();
    }

    @PreDestroy
    public void destroy() {
        this.metadataManager = null;
    }

}
