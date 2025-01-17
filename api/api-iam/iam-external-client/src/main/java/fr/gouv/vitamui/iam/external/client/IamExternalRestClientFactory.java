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
package fr.gouv.vitamui.iam.external.client;

import fr.gouv.vitamui.commons.rest.client.accesscontract.AccessContractExternalRestClient;
import fr.gouv.vitamui.commons.rest.client.logbook.LogbookExternalWebClient;
import org.springframework.boot.web.client.RestTemplateBuilder;

import fr.gouv.vitamui.commons.rest.client.BaseRestClientFactory;
import fr.gouv.vitamui.commons.rest.client.configuration.HttpPoolConfiguration;
import fr.gouv.vitamui.commons.rest.client.configuration.RestClientConfiguration;
import fr.gouv.vitamui.commons.rest.client.logbook.LogbookExternalRestClient;

/**
 * A Rest client factory to create specialized IAM Rest clients
 *
 *
 */

public class IamExternalRestClientFactory extends BaseRestClientFactory {

    public IamExternalRestClientFactory(final RestClientConfiguration restClientConfiguration, final RestTemplateBuilder restTemplateBuilder) {
        super(restClientConfiguration, restTemplateBuilder);
    }

    public IamExternalRestClientFactory(final RestClientConfiguration restClientConfiguration, final HttpPoolConfiguration httpHostConfiguration,
            final RestTemplateBuilder restTemplateBuilder) {
        super(restClientConfiguration, httpHostConfiguration, restTemplateBuilder);
    }

    public IamStatusExternalRestClient getIamStatusExternalRestClient() {
        return new IamStatusExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public CustomerExternalRestClient getCustomerExternalRestClient() {
        return new CustomerExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public IdentityProviderExternalRestClient getIdentityProviderExternalRestClient() {
        return new IdentityProviderExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public ProfileExternalRestClient getProfileExternalRestClient() {
        return new ProfileExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public GroupExternalRestClient getGroupExternalRestClient() {
        return new GroupExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public TenantExternalRestClient getTenantExternalRestClient() {
        return new TenantExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public UserExternalRestClient getUserExternalRestClient() {
        return new UserExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public UserInfoExternalRestClient getUserInfoInfoExternalRestClient() {
        return new UserInfoExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public OwnerExternalRestClient getOwnerExternalRestClient() {
        return new OwnerExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public SubrogationExternalRestClient getSubrogationExternalRestClient() {
        return new SubrogationExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public CasExternalRestClient getCasExternalRestClient() {
        return new CasExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public ApplicationExternalRestClient getApplicationExternalRestClient() {
        return new ApplicationExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public LogbookExternalRestClient getLogbookExternalRestClient() {
        return new LogbookExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public ExternalParametersExternalRestClient getExternalParametersExternalRestClient() {
        return new ExternalParametersExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public ExternalParamProfileExternalRestClient getExternalParamProfileExternalRestClient() {
        return new ExternalParamProfileExternalRestClient(getRestTemplate(), getBaseUrl());
    }

    public AccessContractExternalRestClient getAccessContractExternalRestClient() {
        return new AccessContractExternalRestClient(getRestTemplate(), getBaseUrl());
    }


}
