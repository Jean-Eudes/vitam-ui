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
package fr.gouv.vitamui.ingest.internal.client;


import fr.gouv.vitam.common.model.AuditOptions;
import fr.gouv.vitamui.commons.api.CommonConstants;
import fr.gouv.vitamui.commons.api.domain.PaginatedValuesDto;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.rest.client.BasePaginatingAndSortingRestClient;
import fr.gouv.vitamui.commons.rest.client.InternalHttpContext;
import fr.gouv.vitamui.commons.vitam.api.dto.LogbookOperationDto;
import fr.gouv.vitamui.ingest.common.rest.RestApi;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.InputStream;
import java.util.List;

/**
 * Ingest Streaming Internal REST Client.
 */
public class IngestStreamingInternalRestClient
    extends BasePaginatingAndSortingRestClient<LogbookOperationDto, InternalHttpContext> {

    private static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(IngestStreamingInternalRestClient.class);

    public IngestStreamingInternalRestClient(final RestTemplate restTemplate, final String baseUrl) {
        super(restTemplate, baseUrl);
    }

    @Override
    public String getPathUrl() {
        return RestApi.V1_INGEST;
    }

    @Override
    protected Class<LogbookOperationDto> getDtoClass() {
        return LogbookOperationDto.class;
    }

    @Override
    protected ParameterizedTypeReference<List<LogbookOperationDto>> getDtoListClass() {
        return new ParameterizedTypeReference<List<LogbookOperationDto>>() {
        };
    }

    @Override
    protected ParameterizedTypeReference<PaginatedValuesDto<LogbookOperationDto>> getDtoPaginatedClass() {
        return new ParameterizedTypeReference<PaginatedValuesDto<LogbookOperationDto>>() {
        };
    }

    public ResponseEntity<Void> streamingUpload(final InternalHttpContext context, String originalFileName,
        InputStream inputStream,
        final String contextId,
        final String action) {
        LOGGER.debug("Calling upload using streaming process");
        final UriComponentsBuilder uriBuilder =
            UriComponentsBuilder.fromHttpUrl(getUrl() + RestApi.INGEST_UPLOAD_V2);

        final MultiValueMap<String, String> headersList = new HttpHeaders();
        headersList.addAll(buildHeaders(context));
        headersList.add(CommonConstants.X_CONTEXT_ID, contextId);
        headersList.add(CommonConstants.X_ACTION, action);
        headersList.add(CommonConstants.X_ORIGINAL_FILENAME_HEADER, originalFileName);

        HttpHeaders headersParams = new HttpHeaders();
        headersParams.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headersParams.addAll(headersList);

        final HttpEntity<InputStreamResource> request =
            new HttpEntity<>(new InputStreamResource(inputStream), headersParams);

        final ResponseEntity<Void> response =
            restTemplate.exchange(uriBuilder.toUriString(), HttpMethod.POST,
                request, Void.class);
        LOGGER.debug("The response on ingest is {} ", response.toString());
        return response;
    }
}
