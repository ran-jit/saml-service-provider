# SAML Service Provider (SSO)

### SSO
Single sign-on (SSO) is an authentication process that allows a user to access multiple applications with one set of login credentials.

#### SSO advantages:
* Eliminates credentials, reauthentication and help desk requests.
* Improves compliance and security capabilities.
* Provides detailed user access reporting.


### SAML
Security Assertion Markup Language (SAML) is an XML-based framework for authentication and authorization between two entities: a Service Provider and an Identity Provider. The Service Provider agrees to trust the Identity Provider to authenticate users. In return, the Identity provider generates an authentication assertion, which indicates that a user has been authenticated.

SAML is a standard single sign-on (SSO) format. Authentication information is exchanged through digitally signed XML documents. It's a complex single sign-on (SSO) implementation that enables seamless authentication, mostly between businesses and enterprises.

With SAML, you don't have to worry about typing in authentication credentials or remembering and resetting passwords.

### SAML requirements

| SSO considerations              | Preferences                                                          |
|---------------------------------|----------------------------------------------------------------------|
| Scope of user credentials (IdP) | Should be all users.                                                 |
| Type of connection	          | Both IdP initiated and SP initiated.                                 |
| Expected NameID value format	  | Supports: EMAIL, TRANSIENT, PERSISTENT, UNSPECIFIED. default: EMAIL. |
| Expected attributes             | Configurable.                                                        |

more details.. https://github.com/ran-jit/saml-service-provider/wiki
