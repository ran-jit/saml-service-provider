package service.provider.exception;

import org.apache.catalina.util.URLEncoder;
import service.provider.constants.SamlConstants.UrlConstants;
import service.provider.tenant.identifier.TenantIdentifier.TenantCode;

import java.nio.charset.StandardCharsets;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class TenantNotExistsException extends RuntimeException {
    private static final long serialVersionUID = 420705614681491512L;

    private final String identifier;
    private final TenantCode tenantCode;

    private static final URLEncoder URL_ENCODER = new URLEncoder();

    public TenantNotExistsException(String identifier, TenantCode tenantCode) {
        super();
        this.identifier = identifier;
        this.tenantCode = tenantCode;
    }

    @Override
    public String getMessage() {
        String message = String.format("%s={'message':'Invalid request','errorCode':'%s','identifier':'%s'}&%s=%s", UrlConstants.MESSAGE_PARAM, this.tenantCode.getErrorCode(), this.identifier, UrlConstants.JSON_PARAM, Boolean.TRUE);
        return URL_ENCODER.encode(message, StandardCharsets.UTF_8);
    }

}
