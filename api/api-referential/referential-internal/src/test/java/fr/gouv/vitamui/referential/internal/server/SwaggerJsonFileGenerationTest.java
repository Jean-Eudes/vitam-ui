/**
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2019-2020)
 * and the signatories of the "VITAM - Accord du Contributeur" agreement.
 *
 * contact@programmevitam.fr
 *
 * This software is a computer program whose purpose is to implement
 * implement a digital archiving front-office system for the secure and
 * efficient high volumetry VITAM solution.
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL-C
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 *
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 *
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL-C license and that you accept its terms.
 */
package fr.gouv.vitamui.referential.internal.server;


import fr.gouv.vitam.access.external.client.AccessExternalClient;
import fr.gouv.vitam.access.external.client.AdminExternalClient;
import fr.gouv.vitamui.commons.api.identity.ServerIdentityConfiguration;
import fr.gouv.vitamui.commons.rest.RestExceptionHandler;
import fr.gouv.vitamui.commons.rest.configuration.SwaggerConfiguration;
import fr.gouv.vitamui.commons.test.rest.AbstractSwaggerJsonFileGenerationTest;
import fr.gouv.vitamui.iam.security.service.InternalSecurityService;
import fr.gouv.vitamui.referential.internal.server.accesscontract.AccessContractInternalService;
import fr.gouv.vitamui.referential.internal.server.agency.AgencyInternalService;
import fr.gouv.vitamui.referential.internal.server.context.ContextInternalService;
import fr.gouv.vitamui.referential.internal.server.fileformat.FileFormatInternalService;
import fr.gouv.vitamui.referential.internal.server.ingestcontract.IngestContractInternalService;
import fr.gouv.vitamui.referential.internal.server.logbookmanagement.LogbookManagementOperationInternalService;
import fr.gouv.vitamui.referential.internal.server.managementcontract.ManagementContractInternalService;
import fr.gouv.vitamui.referential.internal.server.ontology.OntologyInternalService;
import fr.gouv.vitamui.referential.internal.server.operation.OperationInternalService;
import fr.gouv.vitamui.referential.internal.server.probativevalue.ProbativeValueInternalService;
import fr.gouv.vitamui.referential.internal.server.profile.ProfileInternalService;
import fr.gouv.vitamui.referential.internal.server.rule.RuleInternalService;
import fr.gouv.vitamui.referential.internal.server.securityprofile.SecurityProfileInternalService;
import fr.gouv.vitamui.referential.internal.server.unit.UnitInternalService;
import org.junit.runner.RunWith;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * Swagger JSON Generation.
 * With this test class, we can generate the swagger json file without launching a full SpringBoot app.
 *
 */
@RunWith(SpringRunner.class)
@WebMvcTest
@Import(value = { ServerIdentityConfiguration.class, SwaggerConfiguration.class })
@ActiveProfiles("test, swagger")
public class SwaggerJsonFileGenerationTest extends AbstractSwaggerJsonFileGenerationTest {
    @MockBean
    private RestExceptionHandler restExceptionHandler;

    @MockBean
    private AdminExternalClient adminExternalClient;

    @MockBean(name = "accessExternalClient")
    private AccessExternalClient accessExternalClient;

    @MockBean
    private AccessContractInternalService accessContractInternalService;

    @MockBean
    private IngestContractInternalService ingestContractInternalService;

    @MockBean
    private AgencyInternalService agencyInternalService;

    @MockBean
    private InternalSecurityService internalSecurityService;

    @MockBean
    private FileFormatInternalService fileFormatInternalService;

    @MockBean
    private OntologyInternalService ontologyInternalService;

    @MockBean
    private ContextInternalService contextInternalService;

    @MockBean
    private SecurityProfileInternalService securityProfileInternalService;

    @MockBean
    private OperationInternalService operationInternalService;

    @MockBean
    private AuthenticationProvider authenticationProvider;

    @MockBean
    private UnitInternalService unitInternalService;

    @MockBean
    private ManagementContractInternalService managementContractInternalService;

    @MockBean
    private ProfileInternalService profileInternalService;

    @MockBean
    private ProbativeValueInternalService probativeValueInternalService;

    @MockBean
    private RuleInternalService ruleInternalService;

    @MockBean
    private LogbookManagementOperationInternalService logbookManagementOperationInternalService;
}
