package fr.gouv.vitamui.cas.authentication;

import fr.gouv.vitamui.cas.provider.ProvidersService;
import fr.gouv.vitamui.cas.util.Constants;
import fr.gouv.vitamui.cas.util.Utils;
import fr.gouv.vitamui.cas.BaseWebflowActionTest;
import fr.gouv.vitamui.cas.x509.X509AttributeMapping;
import fr.gouv.vitamui.commons.api.CommonConstants;
import fr.gouv.vitamui.commons.api.domain.AddressDto;
import fr.gouv.vitamui.commons.api.domain.GroupDto;
import fr.gouv.vitamui.commons.api.domain.ProfileDto;
import fr.gouv.vitamui.commons.api.domain.Role;
import fr.gouv.vitamui.commons.api.enums.UserStatusEnum;
import fr.gouv.vitamui.commons.api.enums.UserTypeEnum;
import fr.gouv.vitamui.commons.api.identity.ServerIdentityAutoConfiguration;
import fr.gouv.vitamui.commons.api.utils.CasJsonWrapper;
import fr.gouv.vitamui.commons.rest.client.ExternalHttpContext;
import fr.gouv.vitamui.commons.security.client.dto.AuthUserDto;
import fr.gouv.vitamui.iam.common.dto.IdentityProviderDto;
import fr.gouv.vitamui.iam.common.utils.IdentityProviderHelper;
import fr.gouv.vitamui.iam.external.client.CasExternalRestClient;
import lombok.val;
import org.apereo.cas.adaptors.x509.authentication.principal.X509CertificateCredential;
import org.apereo.cas.authentication.SurrogateUsernamePasswordCredential;
import org.apereo.cas.authentication.credential.UsernamePasswordCredential;
import org.apereo.cas.authentication.principal.ClientCredential;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.context.session.SessionStore;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.*;

import static fr.gouv.vitamui.commons.api.CommonConstants.IDENTIFIER_ATTRIBUTE;
import static fr.gouv.vitamui.commons.api.CommonConstants.SUPER_USER_ATTRIBUTE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests {@link UserPrincipalResolver}.
 *
 *
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = ServerIdentityAutoConfiguration.class)
@TestPropertySource(locations = "classpath:/application-test.properties")
public final class UserPrincipalResolverTest extends BaseWebflowActionTest {

    private static final String PROVIDER_NAME = "google";
    private static final String MAIL = "mail";
    private static final String IDENTIFIER = "identifier";

    private static final String USERNAME = "jleleu@test.com";
    private static final String ADMIN = "admin@test.com";
    private static final String IDENTIFIER_VALUE = "007";

    private static final String PWD = "password";

    private static final String USERNAME_ID = "jleleu";
    private static final String ADMIN_ID = "admin";

    private static final String ROLE_NAME = "role1";

    private static final String PROVIDER_ID = "providerId";

    private UserPrincipalResolver resolver;

    private CasExternalRestClient casExternalRestClient;

    private PrincipalFactory principalFactory;

    private SessionStore sessionStore;

    private IdentityProviderHelper identityProviderHelper;

    private ProvidersService providersService;

    @Before
    public void setUp() {
        super.setUp();

        casExternalRestClient = mock(CasExternalRestClient.class);
        val utils = new Utils(null, 0, null, null, "");
        principalFactory = new DefaultPrincipalFactory();
        sessionStore = mock(SessionStore.class);
        identityProviderHelper = mock(IdentityProviderHelper.class);
        providersService = mock(ProvidersService.class);
        val emailMapping = new X509AttributeMapping("subject_dn", null, null);
        val identifierMapping = new X509AttributeMapping("issuer_dn", null, null);
        resolver = new UserPrincipalResolver(principalFactory, casExternalRestClient, utils, sessionStore,
            identityProviderHelper, providersService, emailMapping, identifierMapping, "");
    }

    @Test
    public void testResolveUserSuccessfully() {
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(null), eq(Optional.empty()),
                eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER)))).thenReturn(userProfile(UserStatusEnum.ENABLED));

        val principal = resolver.resolve(new UsernamePasswordCredential(USERNAME, PWD),
            Optional.of(principalFactory.createPrincipal(USERNAME)), Optional.empty());

        assertEquals(USERNAME_ID, principal.getId());
        final Map<String, List<Object>> attributes = principal.getAttributes();
        assertEquals(USERNAME, attributes.get(CommonConstants.EMAIL_ATTRIBUTE).get(0));
        assertEquals(Arrays.asList(ROLE_NAME), attributes.get(CommonConstants.ROLES_ATTRIBUTE));
        assertNull(attributes.get(SUPER_USER_ATTRIBUTE));
    }

    @Test
    public void testResolveX509() {
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(null), eq(Optional.of(IDENTIFIER)),
            eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER)))).thenReturn(userProfile(UserStatusEnum.ENABLED));
        val cert = mock(X509Certificate.class);
        val subjectDn = mock(Principal.class);
        when(subjectDn.getName()).thenReturn(USERNAME);
        when(cert.getSubjectDN()).thenReturn(subjectDn);
        val issuerDn = mock(Principal.class);
        when(issuerDn.getName()).thenReturn(IDENTIFIER);
        when(cert.getIssuerDN()).thenReturn(issuerDn);

        val principal = resolver.resolve(new X509CertificateCredential(new X509Certificate[] { cert }),
            Optional.of(principalFactory.createPrincipal(USERNAME)), Optional.empty());

        assertEquals(USERNAME_ID, principal.getId());
        final Map<String, List<Object>> attributes = principal.getAttributes();
        assertEquals(USERNAME, attributes.get(CommonConstants.EMAIL_ATTRIBUTE).get(0));
        assertEquals(Arrays.asList(ROLE_NAME), attributes.get(CommonConstants.ROLES_ATTRIBUTE));
        assertNull(attributes.get(SUPER_USER_ATTRIBUTE));
    }

    @Test
    public void testResolveAuthnDelegation() {
        val provider = new IdentityProviderDto();
        provider.setId(PROVIDER_ID);
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(PROVIDER_ID), eq(Optional.of(USERNAME)),
            eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER)))).thenReturn(userProfile(UserStatusEnum.ENABLED));
        when(sessionStore.get(any(JEEContext.class), eq(Constants.SURROGATE))).thenReturn(Optional.empty());
        when(providersService.getProviders()).thenReturn(new ArrayList<>());
        when(identityProviderHelper.findByTechnicalName(eq(providersService.getProviders()), eq(PROVIDER_NAME))).thenReturn(Optional.of(provider));

        val principal = resolver.resolve(new ClientCredential(null, PROVIDER_NAME),
            Optional.of(principalFactory.createPrincipal(USERNAME)), Optional.empty());

        assertEquals(USERNAME_ID, principal.getId());
        final Map<String, List<Object>> attributes = principal.getAttributes();
        assertEquals(USERNAME, attributes.get(CommonConstants.EMAIL_ATTRIBUTE).get(0));
        assertEquals(Arrays.asList(ROLE_NAME), attributes.get(CommonConstants.ROLES_ATTRIBUTE));
        assertNull(attributes.get(SUPER_USER_ATTRIBUTE));
    }

    @Test
    public void testResolveAuthnDelegationMailAttribute() {
        val provider = new IdentityProviderDto();
        provider.setId(PROVIDER_ID);
        provider.setMailAttribute(MAIL);
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(PROVIDER_ID), eq(Optional.of("fake")),
            eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER)))).thenReturn(userProfile(UserStatusEnum.ENABLED));
        when(sessionStore.get(any(JEEContext.class), eq(Constants.SURROGATE))).thenReturn(Optional.empty());
        when(identityProviderHelper.findByTechnicalName(eq(providersService.getProviders()), eq(PROVIDER_NAME))).thenReturn(Optional.of(provider));

        val princAttributes = new HashMap<String, List<Object>>();
        princAttributes.put(MAIL, Collections.singletonList(USERNAME));

        val principal = resolver.resolve(new ClientCredential(null, PROVIDER_NAME),
            Optional.of(principalFactory.createPrincipal("fake", princAttributes)), Optional.empty());

        assertEquals(USERNAME_ID, principal.getId());
        final Map<String, List<Object>> attributes = principal.getAttributes();
        assertEquals(USERNAME, attributes.get(CommonConstants.EMAIL_ATTRIBUTE).get(0));
        assertEquals(Arrays.asList(ROLE_NAME), attributes.get(CommonConstants.ROLES_ATTRIBUTE));
        assertNull(attributes.get(SUPER_USER_ATTRIBUTE));
    }

    @Test
    public void testResolveAuthnDelegationIdentifierAttribute() {
        val provider = new IdentityProviderDto();
        provider.setId(PROVIDER_ID);
        provider.setIdentifierAttribute(IDENTIFIER);
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(PROVIDER_ID), eq(Optional.of(IDENTIFIER_VALUE)),
            eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER)))).thenReturn(userProfile(UserStatusEnum.ENABLED));
        when(sessionStore.get(any(JEEContext.class), eq(Constants.SURROGATE))).thenReturn(Optional.empty());
        when(identityProviderHelper.findByTechnicalName(eq(providersService.getProviders()), eq(PROVIDER_NAME))).thenReturn(Optional.of(provider));

        val princAttributes = new HashMap<String, List<Object>>();
        princAttributes.put(IDENTIFIER, Collections.singletonList(IDENTIFIER_VALUE));

        val principal = resolver.resolve(new ClientCredential(null, PROVIDER_NAME),
            Optional.of(principalFactory.createPrincipal(USERNAME, princAttributes)), Optional.empty());

        assertEquals(USERNAME_ID, principal.getId());
        final Map<String, List<Object>> attributes = principal.getAttributes();
        assertEquals(Arrays.asList(ROLE_NAME), attributes.get(CommonConstants.ROLES_ATTRIBUTE));
        assertNull(attributes.get(SUPER_USER_ATTRIBUTE));
    }

    @Test
    public void testResolveAuthnDelegationMailAttributeNoValue() {
        val provider = new IdentityProviderDto();
        provider.setId(PROVIDER_ID);
        provider.setMailAttribute(MAIL);
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(PROVIDER_ID), eq(Optional.of("fake")),
            eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER)))).thenReturn(userProfile(UserStatusEnum.ENABLED));
        when(sessionStore.get(any(JEEContext.class), eq(Constants.SURROGATE))).thenReturn(Optional.empty());
        when(identityProviderHelper.findByTechnicalName(eq(providersService.getProviders()), eq(PROVIDER_NAME))).thenReturn(Optional.of(provider));

        val princAttributes = new HashMap<String, List<Object>>();
        princAttributes.put(MAIL, Collections.emptyList());

        val principal = resolver.resolve(new ClientCredential(null, PROVIDER_NAME),
            Optional.of(principalFactory.createPrincipal("fake", princAttributes)), Optional.empty());

        assertEquals("nobody", principal.getId());
    }

    @Test
    public void testResolveAuthnDelegationIdentifierAttributeNoValue() {
        val provider = new IdentityProviderDto();
        provider.setId(PROVIDER_ID);
        provider.setIdentifierAttribute(IDENTIFIER_ATTRIBUTE);
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(PROVIDER_ID), eq(Optional.of("fake")),
            eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER)))).thenReturn(userProfile(UserStatusEnum.ENABLED));
        when(sessionStore.get(any(JEEContext.class), eq(Constants.SURROGATE))).thenReturn(Optional.empty());
        when(identityProviderHelper.findByTechnicalName(eq(providersService.getProviders()), eq(PROVIDER_NAME))).thenReturn(Optional.of(provider));

        val princAttributes = new HashMap<String, List<Object>>();
        princAttributes.put(IDENTIFIER, Collections.emptyList());

        val principal = resolver.resolve(new ClientCredential(null, PROVIDER_NAME),
            Optional.of(principalFactory.createPrincipal("fake", princAttributes)), Optional.empty());

        assertEquals("nobody", principal.getId());
    }
    @Test
    public void testResolveSurrogateUser() {
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(null), eq(Optional.empty()),
            eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER + "," + CommonConstants.SURROGATION_PARAMETER))))
            .thenReturn(userProfile(UserStatusEnum.ENABLED));
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(ADMIN), eq(null), eq(Optional.empty()),
            eq(Optional.empty()))).thenReturn(adminProfile());

        val credential = new SurrogateUsernamePasswordCredential();
        credential.setUsername(ADMIN);
        credential.setSurrogateUsername(USERNAME);
        val principal = resolver.resolve(credential, Optional.of(principalFactory.createPrincipal(ADMIN)), Optional.empty());

        assertEquals(USERNAME_ID, principal.getId());
        final Map<String, List<Object>> attributes = principal.getAttributes();
        assertEquals(USERNAME, attributes.get(CommonConstants.EMAIL_ATTRIBUTE).get(0));
        assertEquals(Arrays.asList(ROLE_NAME), attributes.get(CommonConstants.ROLES_ATTRIBUTE));
        assertEquals(ADMIN, attributes.get(SUPER_USER_ATTRIBUTE).get(0));
    }

    @Test
    public void testResolveAuthnDelegationSurrogate() {
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(null), eq(Optional.empty()),
            eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER + "," + CommonConstants.SURROGATION_PARAMETER))))
            .thenReturn(userProfile(UserStatusEnum.ENABLED));
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(ADMIN), eq(null), eq(Optional.empty()),
            eq(Optional.empty()))).thenReturn(adminProfile());
        when(sessionStore.get(any(JEEContext.class), eq(Constants.SURROGATE))).thenReturn(Optional.of(USERNAME));
        when(identityProviderHelper.findByTechnicalName(eq(providersService.getProviders()), eq(PROVIDER_NAME))).thenReturn(Optional.of(new IdentityProviderDto()));

        val  principal = resolver.resolve(new ClientCredential(null, PROVIDER_NAME), Optional.of(principalFactory.createPrincipal(ADMIN)), Optional.empty());

        assertEquals(USERNAME_ID, principal.getId());
        final Map<String, List<Object>> attributes = principal.getAttributes();
        assertEquals(USERNAME, attributes.get(CommonConstants.EMAIL_ATTRIBUTE).get(0));
        assertEquals(Arrays.asList(ROLE_NAME), attributes.get(CommonConstants.ROLES_ATTRIBUTE));
        assertEquals(ADMIN, attributes.get(SUPER_USER_ATTRIBUTE).get(0));
    }

    @Test
    public void testResolveAuthnDelegationSurrogateMailAttribute() {
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(null), eq(Optional.empty()),
            eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER + "," + CommonConstants.SURROGATION_PARAMETER))))
            .thenReturn(userProfile(UserStatusEnum.ENABLED));
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(ADMIN), eq(null), eq(Optional.empty()),
            eq(Optional.empty()))).thenReturn(adminProfile());
        when(sessionStore.get(any(JEEContext.class), eq(Constants.SURROGATE))).thenReturn(Optional.of(USERNAME));
        val provider = new IdentityProviderDto();
        provider.setMailAttribute(MAIL);
        when(identityProviderHelper.findByTechnicalName(eq(providersService.getProviders()), eq(PROVIDER_NAME))).thenReturn(Optional.of(provider));

        val princAttributes = new HashMap<String, List<Object>>();
        princAttributes.put(MAIL, Collections.singletonList(ADMIN));

        val  principal = resolver.resolve(new ClientCredential(null, PROVIDER_NAME),
            Optional.of(principalFactory.createPrincipal("fake", princAttributes)), Optional.empty());

        assertEquals(USERNAME_ID, principal.getId());
        final Map<String, List<Object>> attributes = principal.getAttributes();
        assertEquals(USERNAME, attributes.get(CommonConstants.EMAIL_ATTRIBUTE).get(0));
        assertEquals(Arrays.asList(ROLE_NAME), attributes.get(CommonConstants.ROLES_ATTRIBUTE));
        assertEquals(ADMIN, attributes.get(SUPER_USER_ATTRIBUTE).get(0));
    }

    @Test
    public void testResolveAuthnDelegationSurrogateMailAttributeNoMail() {
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(null), eq(Optional.empty()),
            eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER + "," + CommonConstants.SURROGATION_PARAMETER))))
            .thenReturn(userProfile(UserStatusEnum.ENABLED));
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(ADMIN), eq(null), eq(Optional.empty()),
            eq(Optional.empty()))).thenReturn(adminProfile());
        when(sessionStore.get(any(JEEContext.class), eq(Constants.SURROGATE))).thenReturn(Optional.of(USERNAME));
        val provider = new IdentityProviderDto();
        provider.setMailAttribute(MAIL);
        when(identityProviderHelper.findByTechnicalName(eq(providersService.getProviders()), eq(PROVIDER_NAME))).thenReturn(Optional.of(provider));

        val  principal = resolver.resolve(new ClientCredential(null, PROVIDER_NAME), Optional.of(principalFactory.createPrincipal("fake")), Optional.empty());

        assertEquals("nobody", principal.getId());
    }

    @Test
    public void testResolveAddressDeserializeSuccessfully() {
        AuthUserDto authUserDto = userProfile(UserStatusEnum.ENABLED);
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(null), eq(Optional.empty()), eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER))))
                .thenReturn(authUserDto);

        val principal = resolver.resolve(new UsernamePasswordCredential(USERNAME, PWD),
            Optional.of(principalFactory.createPrincipal(USERNAME)), Optional.empty());

        assertEquals(USERNAME_ID, principal.getId());
        AddressDto addressDto = (AddressDto) ((CasJsonWrapper) principal.getAttributes().get(CommonConstants.ADDRESS_ATTRIBUTE).get(0)).getData();
        assertThat(addressDto).isEqualToComparingFieldByField(authUserDto.getAddress());
        assertNull(principal.getAttributes().get(SUPER_USER_ATTRIBUTE));
    }

    @Test
    public void testNoUser() {
        val provider = new IdentityProviderDto();
        provider.setId(PROVIDER_ID);
        when(identityProviderHelper.findByUserIdentifier(providersService.getProviders(), USERNAME)).thenReturn(Optional.of(provider));
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(PROVIDER_ID), eq(Optional.empty()), eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER))))
            .thenReturn(null);

        assertNull(resolver.resolve(new UsernamePasswordCredential(USERNAME, PWD),
            Optional.of(principalFactory.createPrincipal(USERNAME)), Optional.empty()));
    }

    @Test
    public void testDisabledUser() {
        val provider = new IdentityProviderDto();
        provider.setId(PROVIDER_ID);
        when(identityProviderHelper.findByUserIdentifier(providersService.getProviders(), USERNAME)).thenReturn(Optional.of(provider));
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(PROVIDER_ID), eq(Optional.empty()), eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER))))
            .thenReturn(userProfile(UserStatusEnum.DISABLED));

        assertNull(resolver.resolve(new UsernamePasswordCredential(USERNAME, PWD),
            Optional.of(principalFactory.createPrincipal(USERNAME)), Optional.empty()));
    }

    @Test
    public void testUserCannotLogin() {
        val provider = new IdentityProviderDto();
        provider.setId(PROVIDER_ID);
        when(identityProviderHelper.findByUserIdentifier(providersService.getProviders(), USERNAME)).thenReturn(Optional.of(provider));
        when(casExternalRestClient.getUser(any(ExternalHttpContext.class), eq(USERNAME), eq(PROVIDER_ID), eq(Optional.empty()), eq(Optional.of(CommonConstants.AUTH_TOKEN_PARAMETER))))
            .thenReturn(userProfile(UserStatusEnum.BLOCKED));

        assertNull(resolver.resolve(new UsernamePasswordCredential(USERNAME, PWD),
            Optional.of(principalFactory.createPrincipal(USERNAME)), Optional.empty()));
    }

    private AuthUserDto adminProfile() {
        return profile(UserStatusEnum.ENABLED, ADMIN_ID);
    }

    private AuthUserDto userProfile(final UserStatusEnum status) {
        return profile(status, USERNAME_ID);
    }

    private AuthUserDto profile(final UserStatusEnum status, final String id) {
        val user = new AuthUserDto();
        user.setId(id);
        user.setStatus(status);
        user.setType(UserTypeEnum.NOMINATIVE);
        AddressDto address = new AddressDto();
        address.setStreet("73 rue du faubourg poissonnière");
        address.setZipCode("75009");
        address.setCity("Paris");
        address.setCountry("France");
        user.setAddress(address);
        val profile = new ProfileDto();
        profile.setRoles(Arrays.asList(new Role(ROLE_NAME)));
        val group = new GroupDto();
        group.setProfiles(Arrays.asList(profile));
        user.setProfileGroup(group);
        user.setCustomerId("customerId");
        return user;
    }
}
