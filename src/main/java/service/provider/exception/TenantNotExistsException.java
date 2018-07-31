package service.provider.exception;

import org.apache.catalina.util.URLEncoder;
import service.provider.tenant.identifier.TenantIdentifier.TenantCode;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class TenantNotExistsException extends RuntimeException {
    private static final long serialVersionUID = 8266028257891393191L;

    private final HttpServletRequest request;
    private final TenantCode tenantCode;

    private static final URLEncoder URL_ENCODER = new URLEncoder();

    public TenantNotExistsException(HttpServletRequest request, TenantCode tenantCode) {
        super();
        this.request = request;
        this.tenantCode = tenantCode;
    }

    @Override
    public String getMessage() {
        return URL_ENCODER.encode(String.format("{message: Invalid request, errorCode: %s, requestUrl: %s}", this.tenantCode.getErrorCode(), this.request.getRequestURL().toString()), StandardCharsets.UTF_8);
    }

}
