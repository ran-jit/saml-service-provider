package service.provider.tenant.identifier.impl;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class UrlPathTenantIdentifier {

//    private final String loginProcessingUrl;
//    private final String logoutProcessingUrl;
//
//    public UrlPathTenantIdentifier(String loginProcessingUrl, String logoutProcessingUrl) {
//        this.loginProcessingUrl = loginProcessingUrl;
//        this.logoutProcessingUrl = logoutProcessingUrl;
//    }
//
//    @Override
//    public TenantInfo identifyTenant(HttpServletRequest request) throws TenantNotExistsException {
//        String requestUri = request.getRequestURI();
//        String tenantId;
//        if (requestUri.startsWith(this.loginProcessingUrl)) {
//            tenantId = getTenantId(request, this.loginProcessingUrl);
//        } else if (requestUri.startsWith(this.logoutProcessingUrl)) {
//            tenantId = getTenantId(request, this.logoutProcessingUrl);
//        } else {
//            throw new TenantNotExistsException(TenantCode.URL, request.getRequestURL().toString());
//        }
//
//        return super.identifyTenant(request, tenantId, TenantCode.URL);
//    }
//
//    @Override
//    protected String getTenantId(HttpServletRequest request) {
//        return null;
//    }
//
//    @Override
//    public TenantInfo updateMetadata(TenantInfo tenantInfo, String remoteEntityId) {
//        return null;
//    }
//
//    private String getTenantId(HttpServletRequest request, String filterUri) {
//        int filterIndex = request.getRequestURI().indexOf(filterUri);
//        return (filterIndex != -1) ? request.getRequestURI().substring(filterIndex + (filterUri.length())) : null;
//    }

}
