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

import java.net.URI;
import java.util.List;
import java.util.Map;

import org.apache.http.client.utils.URIBuilder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import fr.gouv.vitamui.commons.api.CommonConstants;
import fr.gouv.vitamui.commons.api.domain.PaginatedValuesDto;
import fr.gouv.vitamui.commons.api.domain.UserDto;
import fr.gouv.vitamui.commons.api.domain.UserInfoDto;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.rest.client.BasePaginatingAndSortingRestClient;
import fr.gouv.vitamui.commons.rest.client.ExternalHttpContext;
import fr.gouv.vitamui.iam.common.rest.RestApi;

/**
 * A REST client to check existence, read, create, update and delete the user infos.
 *
 *
 */
public class UserInfoExternalRestClient extends BasePaginatingAndSortingRestClient<UserInfoDto, ExternalHttpContext> {

    private static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(UserInfoExternalRestClient.class);

    public UserInfoExternalRestClient(final RestTemplate restTemplate, final String baseUrl) {
        super(restTemplate, baseUrl);
    }

    public UserInfoDto getMe(final ExternalHttpContext context) {
        LOGGER.debug("GetMe");

        final HttpEntity<?> request = new HttpEntity<>(buildHeaders(context));
        final URIBuilder uriBuilder = getUriBuilderFromPath(CommonConstants.PATH_ME);
        final URI uri = buildUriBuilder(uriBuilder);

        final ResponseEntity<UserInfoDto> response = restTemplate.exchange(uri, HttpMethod.GET, request,getDtoClass());
        checkResponse(response);
        return response.getBody();
    }

    public UserInfoDto patchMe(final ExternalHttpContext context, final Map<String, Object> partialDto) {
        LOGGER.debug("Patch me partialDto={}");
        final URIBuilder uriBuilder = getUriBuilderFromPath(CommonConstants.PATH_ME);
        final MultiValueMap<String, String> headers = buildHeaders(context);

        final URI uri = buildUriBuilder(uriBuilder);
        final HttpEntity<Map<String, Object>> request = new HttpEntity<>(partialDto, headers);
        final ResponseEntity<UserInfoDto> response = restTemplate.exchange(uri, HttpMethod.PATCH, request, getDtoClass());
        checkResponse(response);
        return response.getBody();
    }



    @Override
    public String getPathUrl() {
        return RestApi.V1_USERS_INFO_URL;
    }

    @Override
    protected Class<UserInfoDto> getDtoClass() {
        return UserInfoDto.class;
    }

    @Override
    protected ParameterizedTypeReference<List<UserInfoDto>> getDtoListClass() {
        return new ParameterizedTypeReference<>() {
        };
    }

    @Override
    protected ParameterizedTypeReference<PaginatedValuesDto<UserInfoDto>> getDtoPaginatedClass() {
        return new ParameterizedTypeReference<>() {
        };
    }

}
