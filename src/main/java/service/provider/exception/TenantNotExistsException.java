package service.provider.exception;

import service.provider.tenant.identifier.TenantIdentifier.TenantCode;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class TenantNotExistsException extends Exception {

    private static final long serialVersionUID = -7652370760764429701L;

    public TenantNotExistsException(TenantCode errorCode, String message) {
        super(String.format("Invalid request: { Error Code: %d, URL: %s }.", errorCode.getErrorCode(), message));
    }

}
