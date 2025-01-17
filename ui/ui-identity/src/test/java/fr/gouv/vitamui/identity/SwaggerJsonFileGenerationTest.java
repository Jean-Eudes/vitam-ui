package fr.gouv.vitamui.identity;

import org.junit.runner.RunWith;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import fr.gouv.vitamui.commons.api.identity.ServerIdentityConfiguration;
import fr.gouv.vitamui.commons.rest.RestExceptionHandler;
import fr.gouv.vitamui.commons.rest.configuration.SwaggerConfiguration;
import fr.gouv.vitamui.commons.test.rest.AbstractSwaggerJsonFileGenerationTest;
import fr.gouv.vitamui.identity.service.CustomerService;
import fr.gouv.vitamui.identity.service.GroupService;
import fr.gouv.vitamui.identity.service.IdentityCommonService;
import fr.gouv.vitamui.identity.service.OwnerService;
import fr.gouv.vitamui.identity.service.ProfileService;
import fr.gouv.vitamui.identity.service.ProviderService;
import fr.gouv.vitamui.identity.service.TenantService;
import fr.gouv.vitamui.identity.service.UserInfoService;
import fr.gouv.vitamui.identity.service.UserService;
import fr.gouv.vitamui.ui.commons.security.SecurityConfig;

/**
 * Swagger JSON Generation.
 * With this test class, we can generate the swagger json file without launching a full SpringBoot app.
 *
 */
@RunWith(SpringRunner.class)
@WebMvcTest
@Import(value = { SecurityConfig.class, ServerIdentityConfiguration.class, SwaggerConfiguration.class })
@ActiveProfiles("test, swagger")
public class SwaggerJsonFileGenerationTest extends AbstractSwaggerJsonFileGenerationTest {

    @MockBean
    private RestExceptionHandler restExceptionHandler;

    @MockBean
    private CustomerService customerService;

    @MockBean
    private GroupService groupService;

    @MockBean
    private IdentityCommonService identityCommonService;

    @MockBean
    private OwnerService ownerService;

    @MockBean
    private ProfileService profileService;

    @MockBean
    private ProviderService providerService;

    @MockBean
    private TenantService tenantService;

    @MockBean
    private UserService userService;

    @MockBean
    private UserInfoService userInfoService;


}
