package service.provider.constants;

import com.google.common.collect.Sets;

import java.util.Set;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public interface SamlConstants {

    interface MetadataConstants {
        String CONTENT_TYPE = "application/samlmetadata+xml";
        String FILE_NAME = "attachment; filename=\"%s-metadata.xml\"";
    }

    enum MetadataResourceType {
        FILE, URL
    }

    enum NameIdType {
        EMAIL, TRANSIENT, PERSISTENT, UNSPECIFIED
    }

    interface BeanConstants {
        String METADATA = "metadata";
        String INITIALIZE = "initialize";
        String PARSER_POOL_HOLDER = "parserPoolHolder";
        String WEB_PROCESSING_FILTER = "samlWebSSOProcessingFilter";
    }

    interface ValueConstants {
        String IS_LOAD_BALANCER_ENV = "${server.loadBalancerEnv:false}";

        String METADATA_ENTITY_ID = "${sp.entityId}";
        String METADATA_NAME_ID = "#{'${sp.nameId}'.split(',')}";

        String ENTITY_BASE_URL = "${sp.url.base}";
        String HOME_PAGE_URL = "${sp.url.homePage}";
        String ERROR_PAGE_URL = "${sp.url.errorPage:/public/error.htm}";

        String SSL_ENABLED = "${server.ssl.enabled}";
        String SSL_KEYSTORE = "${server.ssl.key-store}";
        String SSL_KEYSTORE_ALIAS = "${server.ssl.key-alias}";
        String SSL_KEYSTORE_PASSWORD = "${server.ssl.key-store-password}";

        String LOGIN_PROCESSING_URL = "${sp.url.login}";
        String LOGOUT_PROCESSING_URL = "${sp.url.logout}";

        String METADATA_PROCESSING_URL = "${sp.url.metadata}";
        String LOGIN_FILTER_PROCESSING_URL = "${sp.url.loginFilter}";
        String LOGOUT_FILTER_PROCESSING_URL = "${sp.url.logoutFilter}";

        String AUTH_SUCCESS_REDIRECTION_URL = "${sp.url.authSuccessRedirection}";
        String RESPONSE_SKEW = "${sp.responseSkew:90}";

        String TENANT_IDENTIFIER = "${tenant.identifier:DNS}";
        String TENANT_IDENTIFIER_PARAM = "${tenant.identifierParam:tenant}";

        String DOMAINS_FILTER_FILE = "${util.domainFile:domains.xml}";
    }

    interface UrlConstants {
        String REDIRECT_TO_URL_PARAM = "redirect_to_url";

        String ERROR_PAGE = "/error.html";
        String ERROR_PAGE_FILE = "/public/error.html";
        String MESSAGE_PARAM = "message";
        String JSON_PARAM = "json";

        String COOKIE_JSESSIONID = "JSESSIONID";
    }

    interface UtilConstants {
        String DOMAINS_FILE_NAME = "domains.xml";
        String DOMAINS_TAG_NAME = "domains";
        String DOMAIN_ATTRIBUTE_NAME = "domain";
        Set<String> DOMAIN_TAGS = Sets.newHashSet("tld", "sld");
    }

}
