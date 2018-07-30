package service.provider.config;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpConnectionManager;
import org.apache.commons.httpclient.HttpsURL;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.util.resource.ClasspathResource;
import org.opensaml.util.resource.FilesystemResource;
import org.opensaml.util.resource.HttpResource;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.EmptyKeyManager;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import service.provider.constants.SamlConstants.BeanConstants;
import service.provider.constants.SamlConstants.NameIdType;
import service.provider.constants.SamlConstants.UrlConstants;
import service.provider.constants.SamlConstants.ValueConstants;
import service.provider.filter.SamlLogoutFilter;
import service.provider.filter.SamlMetadataDisplayFilter;
import service.provider.filter.SamlMetadataGeneratorFilter;
import service.provider.manager.MetadataManager;
import service.provider.model.TenantInfo;
import service.provider.service.SamlUserDetailsService;
import service.provider.tenant.identifier.TenantIdentifier;
import service.provider.tenant.identifier.TenantIdentifier.TenantCode;
import service.provider.tenant.identifier.impl.AttributeTenantIdentifier;
import service.provider.tenant.identifier.impl.DnsTenantIdentifier;
import service.provider.util.URLUtil;

import javax.validation.Valid;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.stream.Collectors;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
@Order(1)
@Configuration
@EnableWebSecurity
public class SamlConfig extends WebSecurityConfigurerAdapter {

    private final Boolean isLoadBalancerEnv;

    private final String metadataEntityId;
    private final List<String> nameIdFormat;
    private final String entityBaseUrl;

    private final Boolean sslEnabled;
    private final String sslKeyStore;
    private final String sslKeyStoreAlias;
    private final String sslKeyStorePassword;

    private final String loginProcessingUrl;
    private final String logoutProcessingUrl;

    private final String loginFilterProcessingUrl;
    private final String logoutFilterProcessingUrl;
    private final String metadataProcessingUrl;

    private final String authSuccessRedirectionUrl;
    private final String homePageUrl;
    private final String errorPageUrl;
    private final Integer responseSkew;

    private final String tenantIdentifier;
    private final String tenantIdentifierParam;

    private final String domainsFilterFile;

    private static final Log LOGGER = LogFactory.getLog(SamlConfig.class);

    public SamlConfig(@Value(value = ValueConstants.IS_LOAD_BALANCER_ENV) Boolean isLoadBalancerEnv,
                      @Value(value = ValueConstants.METADATA_ENTITY_ID) String metadataEntityId,
                      @Value(value = ValueConstants.METADATA_NAME_ID) List<String> nameIdFormat,
                      @Value(value = ValueConstants.ENTITY_BASE_URL) String entityBaseUrl,
                      @Value(value = ValueConstants.SSL_KEYSTORE) String sslKeyStore,
                      @Value(value = ValueConstants.SSL_KEYSTORE_ALIAS) String sslKeyStoreAlias,
                      @Value(value = ValueConstants.SSL_KEYSTORE_PASSWORD) String sslKeyStorePassword,
                      @Value(value = ValueConstants.SSL_ENABLED) Boolean sslEnabled,
                      @Value(value = ValueConstants.LOGIN_PROCESSING_URL) String loginProcessingUrl,
                      @Value(value = ValueConstants.LOGOUT_PROCESSING_URL) String logoutProcessingUrl,
                      @Value(value = ValueConstants.LOGIN_FILTER_PROCESSING_URL) String loginFilterProcessingUrl,
                      @Value(value = ValueConstants.LOGOUT_FILTER_PROCESSING_URL) String logoutFilterProcessingUrl,
                      @Value(value = ValueConstants.METADATA_PROCESSING_URL) String metadataProcessingUrl,
                      @Value(value = ValueConstants.AUTH_SUCCESS_REDIRECTION_URL) String authSuccessRedirectionUrl,
                      @Value(value = ValueConstants.HOME_PAGE_URL) String homePageUrl,
                      @Value(value = ValueConstants.ERROR_PAGE_URL) String errorPageUrl,
                      @Value(value = ValueConstants.RESPONSE_SKEW) Integer responseSkew,
                      @Value(value = ValueConstants.TENANT_IDENTIFIER) String tenantIdentifier,
                      @Value(value = ValueConstants.TENANT_IDENTIFIER_PARAM) String tenantIdentifierParam,
                      @Value(value = ValueConstants.DOMAINS_FILTER_FILE) String domainsFilterFile) {
        this.isLoadBalancerEnv = isLoadBalancerEnv;
        this.metadataEntityId = metadataEntityId;
        this.nameIdFormat = nameIdFormat;
        this.entityBaseUrl = entityBaseUrl;
        this.sslEnabled = sslEnabled;
        this.sslKeyStore = sslKeyStore;
        this.sslKeyStoreAlias = sslKeyStoreAlias;
        this.sslKeyStorePassword = sslKeyStorePassword;
        this.loginProcessingUrl = loginProcessingUrl;
        this.logoutProcessingUrl = logoutProcessingUrl;
        this.loginFilterProcessingUrl = loginFilterProcessingUrl;
        this.logoutFilterProcessingUrl = logoutFilterProcessingUrl;
        this.metadataProcessingUrl = metadataProcessingUrl;
        this.authSuccessRedirectionUrl = authSuccessRedirectionUrl;
        this.homePageUrl = homePageUrl;
        this.errorPageUrl = errorPageUrl;
        this.responseSkew = responseSkew;
        this.tenantIdentifier = tenantIdentifier.replaceAll("\\s+", "").toUpperCase();
        this.tenantIdentifierParam = tenantIdentifierParam;
        this.domainsFilterFile = domainsFilterFile;
    }

    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider provider = new SAMLAuthenticationProvider();
        provider.setUserDetails(samlUserDetailsService());
        provider.setForcePrincipalAsString(false);
        return provider;
    }

    @Bean
    public SAMLUserDetailsService samlUserDetailsService() {
        return new SamlUserDetailsService();
    }

    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint entryPoint = new SAMLEntryPoint();
        entryPoint.setFilterProcessesUrl(this.loginProcessingUrl);
        entryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        return entryPoint;
    }

    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        SamlLogoutFilter filter = new SamlLogoutFilter(this.homePageUrl, this.errorPageUrl, logoutSuccessHandler(), contextLogoutHandler(), contextLogoutHandler());
        filter.setFilterProcessesUrl(this.logoutProcessingUrl);
        return filter;
    }

    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions options = new WebSSOProfileOptions();
        options.setIncludeScoping(false);
        return options;
    }

    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        MetadataDisplayFilter filter = new SamlMetadataDisplayFilter(this.errorPageUrl);
        filter.setFilterProcessesUrl(this.metadataProcessingUrl);
        return filter;
    }

    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() throws Exception {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId(this.metadataEntityId);
        metadataGenerator.setEntityBaseURL(this.entityBaseUrl);
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setKeyManager(keyManager());
        metadataGenerator.setSamlWebSSOFilter(samlWebSSOProcessingFilter());
        metadataGenerator.setSamlLogoutProcessingFilter(samlLogoutProcessingFilter());
        metadataGenerator.setNameID(this.nameIdFormat.stream().map(nameId -> {
            switch (NameIdType.valueOf(nameId)) {
                default:
                case EMAIL:
                    return NameIDType.EMAIL;
                case TRANSIENT:
                    return NameIDType.TRANSIENT;
                case UNSPECIFIED:
                    return NameIDType.UNSPECIFIED;
                case PERSISTENT:
                    return NameIDType.PERSISTENT;
            }
        }).collect(Collectors.toSet()));
        return new SamlMetadataGeneratorFilter(metadataGenerator);
    }

    @Bean(name = BeanConstants.METADATA)
    @Scope(value = BeanDefinition.SCOPE_SINGLETON)
    public MetadataManager metadata(@Valid MetadataConfig metadataConfig) throws MetadataProviderException {
        List<MetadataProvider> providers = null;
        if (CollectionUtils.isNotEmpty(metadataConfig.getIdp())) {
            providers = metadataConfig.getIdp().stream()
                    .map(tenantInfo -> {
                        try {
                            return idpMetadata(tenantInfo);
                        } catch (Exception ex) {
                            LOGGER.error("Error in metadata generation, metadataConfig: " + metadataConfig, ex);
                        }
                        return null;
                    }).collect(Collectors.toList());
        }

        return new MetadataManager(metadataConfig, providers);
    }

    private ExtendedMetadataDelegate idpMetadata(TenantInfo tenantInfo) throws MetadataProviderException, ResourceException {
        Resource resource;
        switch (tenantInfo.getMetadata().getType()) {
            case FILE:
                resource = new FilesystemResource(tenantInfo.getMetadata().getFilePath());
                break;
            case URL:
                resource = new HttpResource(tenantInfo.getMetadata().getFilePath());
                break;
            default:
                resource = new ClasspathResource(tenantInfo.getMetadata().getFilePath());
                break;
        }

        ResourceBackedMetadataProvider metadataProvider = new ResourceBackedMetadataProvider(new Timer(true), resource);
        metadataProvider.setParserPool(parserPool());

        ExtendedMetadata defaultMetadata = new ExtendedMetadata();
        defaultMetadata.setAlias(tenantInfo.getTenantId());

        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setAlias(tenantInfo.getTenantId());
        extendedMetadata.setLocal(true);
        extendedMetadata.setSignMetadata(false);
        extendedMetadata.setIdpDiscoveryEnabled(false);

        Map<String, ExtendedMetadata> metadataMap = Maps.newHashMap();
        metadataMap.put(tenantInfo.getTenantId(), extendedMetadata);

        ExtendedMetadataDelegate metadataDelegate = new ExtendedMetadataDelegate(metadataProvider, defaultMetadata, metadataMap);
        metadataDelegate.setMetadataTrustCheck(tenantInfo.getMetadata().getTrustCheck());
        metadataDelegate.setMetadataRequireSignature(false);
        return metadataDelegate;
    }

    @Bean
    public KeyManager keyManager() {
        if (Boolean.TRUE.equals(this.sslEnabled)) {
            FileSystemResource storeFile = new FileSystemResource(this.sslKeyStore);
            Map<String, String> passwords = Maps.newHashMap();
            passwords.put(this.sslKeyStoreAlias, this.sslKeyStorePassword);
            return new JKSKeyManager(storeFile, this.sslKeyStorePassword, passwords, this.sslKeyStoreAlias);
        } else {
            return new EmptyKeyManager();
        }
    }

    @Bean(name = BeanConstants.WEB_PROCESSING_FILTER)
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter filter = new SAMLProcessingFilter();
        filter.setFilterProcessesUrl(this.loginFilterProcessingUrl);
        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return filter;
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        SimpleUrlAuthenticationSuccessHandler handler = new SimpleUrlAuthenticationSuccessHandler();
        handler.setAlwaysUseDefaultTargetUrl(true);
        handler.setDefaultTargetUrl(this.authSuccessRedirectionUrl);
        return handler;
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new SimpleUrlAuthenticationFailureHandler();
    }

    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        SAMLLogoutProcessingFilter filter = new SAMLLogoutProcessingFilter(logoutSuccessHandler(), contextLogoutHandler());
        filter.setFilterProcessesUrl(this.logoutFilterProcessingUrl);
        return filter;
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        LogoutSuccessHandler handler = new service.provider.handler.LogoutSuccessHandler();
        ((service.provider.handler.LogoutSuccessHandler) handler).setTargetUrlParameter(UrlConstants.REDIRECT_TO_URL_PARAM);
        ((service.provider.handler.LogoutSuccessHandler) handler).setDefaultTargetUrl(this.homePageUrl);
        ((service.provider.handler.LogoutSuccessHandler) handler).setUseReferer(true);
        return handler;
    }

    @Bean
    public SecurityContextLogoutHandler contextLogoutHandler() {
        SecurityContextLogoutHandler handler = new SecurityContextLogoutHandler();
        handler.setInvalidateHttpSession(true);
        handler.setClearAuthentication(true);
        return handler;
    }

    @Bean(initMethod = BeanConstants.INITIALIZE)
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    @Bean(name = BeanConstants.PARSER_POOL_HOLDER)
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }

    @Bean
    public HTTPPostBinding httpPostBinding() {
        return new HTTPPostBinding(parserPool(), velocityEngine());
    }

    @Bean
    public VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine();
    }

    @Bean
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
        return new HTTPRedirectDeflateBinding(parserPool());
    }

    @Bean
    public SAMLProcessor processor() {
        List<SAMLBinding> bindings = Lists.newArrayList();
        bindings.add(httpRedirectDeflateBinding());
        bindings.add(httpPostBinding());
        return new SAMLProcessorImpl(bindings);
    }

    @Bean
    public HttpClient httpClient() {
        return new HttpClient(httpConnectionManager());
    }

    @Bean
    public HttpConnectionManager httpConnectionManager() {
        return new MultiThreadedHttpConnectionManager();
    }

    @Bean
    public static SAMLBootstrap samlBootstrap() {
        return new SAMLBootstrap();
    }

    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    @Bean
    public SAMLContextProvider contextProvider() throws Exception {
        if (Boolean.TRUE.equals(this.isLoadBalancerEnv)) {
            SAMLContextProviderLB provider = new SAMLContextProviderLB();
            URL url = new URL(this.entityBaseUrl);
            provider.setScheme(url.getProtocol());
            provider.setServerName(url.getHost());
            provider.setServerPort(HttpsURL.DEFAULT_PORT);
            provider.setIncludeServerPortInRequestURL(false);
            provider.setContextPath("/");
            provider.setKeyManager(keyManager());
            return provider;
        }
        return new SAMLContextProviderImpl();
    }

    /**
     * SAML 2.0 WebSSO Assertion Consumer
     */
    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        WebSSOProfileConsumerImpl consumer = new WebSSOProfileConsumerImpl();
        consumer.setResponseSkew(this.responseSkew);
        return consumer;
    }

    /**
     * SAML 2.0 Web SSO profile
     */
    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    /**
     * SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
     */
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    /**
     * SAML 2.0 Holder-of-Key Web SSO profile
     */
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder authManagerBuilder) {
        authManagerBuilder.authenticationProvider(samlAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .exceptionHandling()
                .authenticationEntryPoint(samlEntryPoint());
        httpSecurity
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        httpSecurity
                .csrf()
                .disable();
        httpSecurity
                .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
                .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class);
        httpSecurity
                .authorizeRequests()
                .antMatchers(this.loginProcessingUrl).permitAll()
                .antMatchers(this.logoutProcessingUrl).permitAll()
                .antMatchers(this.metadataProcessingUrl).permitAll()
                .antMatchers(this.loginFilterProcessingUrl).permitAll()
                .antMatchers(this.logoutFilterProcessingUrl).permitAll()
                .antMatchers(UrlConstants.ERROR_PAGE).permitAll()
                .antMatchers(UrlConstants.NOT_FOUND_PAGE).permitAll()
                .antMatchers(UrlConstants.INTERNAL_SERVER_PAGE).permitAll()
                .antMatchers("/error").permitAll()
                .anyRequest().authenticated();
        httpSecurity
                .logout()
                .logoutSuccessUrl("/");
    }

    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = Lists.newArrayList();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(this.loginProcessingUrl), samlEntryPoint()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(this.logoutProcessingUrl), samlLogoutFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(this.metadataProcessingUrl), metadataDisplayFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(this.loginFilterProcessingUrl), samlWebSSOProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(this.logoutFilterProcessingUrl), samlLogoutProcessingFilter()));
        return new FilterChainProxy(chains);
    }

    @Bean
    @Scope(value = BeanDefinition.SCOPE_SINGLETON)
    public TenantIdentifier tenantIdentifier() {
        switch (TenantCode.valueOf(this.tenantIdentifier)) {
            default:
            case DNS:
                return new DnsTenantIdentifier(this.entityBaseUrl, this.loginProcessingUrl, this.logoutProcessingUrl, this.loginFilterProcessingUrl, this.logoutFilterProcessingUrl, this.metadataProcessingUrl);
            case ATTRIBUTE:
                return new AttributeTenantIdentifier(this.entityBaseUrl, this.loginProcessingUrl, this.logoutProcessingUrl, this.loginFilterProcessingUrl, this.logoutFilterProcessingUrl, this.metadataProcessingUrl, this.tenantIdentifierParam);
        }
    }

    @Bean
    @Scope(value = BeanDefinition.SCOPE_SINGLETON)
    public URLUtil urlUtil() {
        return new URLUtil(this.domainsFilterFile);
    }

}
