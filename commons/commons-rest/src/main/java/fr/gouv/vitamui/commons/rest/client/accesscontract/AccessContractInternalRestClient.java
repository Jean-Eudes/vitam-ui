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
package fr.gouv.vitamui.commons.rest.client.accesscontract;

import fr.gouv.vitamui.commons.api.CommonConstants;
import fr.gouv.vitamui.commons.api.domain.AccessContractsDto;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.rest.client.AbstractHttpContext;
import fr.gouv.vitamui.commons.rest.client.BaseRestClient;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.List;

/**
 * A REST client to get access contracts.
 *
 */
public class AccessContractInternalRestClient<C extends AbstractHttpContext> extends BaseRestClient<C> {

    static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(AccessContractInternalRestClient.class);

    public AccessContractInternalRestClient(final RestTemplate restTemplate, final String baseUrl) {
        super(restTemplate, baseUrl);
    }

    @Override
    public String getPathUrl() {
        return CommonConstants.API_VERSION_1;
    }

    /**
     * Fetch all access contracts
     *
     * @param context rest context
     */
    public List<AccessContractsDto> getAll(final C context) {
        final MultiValueMap<String, String> headers = buildHeaders(context);
        final HttpEntity<Void> request = new HttpEntity<>(headers);
        final ResponseEntity<List<AccessContractsDto>> response =
            restTemplate.exchange(getUrl() + "/accesscontracts" , HttpMethod.GET, request, new ParameterizedTypeReference<>(){});
        checkResponse(response);
        return response.getBody();
    }

    public AccessContractsDto getAccessContractById(final C context, String identifier) {
        final HttpEntity<Void> request = new HttpEntity<>(buildHeaders(context));
        final ResponseEntity<AccessContractsDto> response = restTemplate.exchange(getUrl() + "/accesscontracts/"+ identifier, HttpMethod.GET, request,
            AccessContractsDto.class);
        checkResponse(response);
        return response.getBody();
    }
}
