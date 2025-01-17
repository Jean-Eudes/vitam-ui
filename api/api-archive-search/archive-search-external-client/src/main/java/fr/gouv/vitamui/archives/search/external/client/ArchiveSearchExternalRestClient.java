/*
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2015-2022)
 *
 * contact.vitam@culture.gouv.fr
 *
 * This software is a computer program whose purpose is to implement a digital archiving back-office system managing
 * high volumetry securely and efficiently.
 *
 * This software is governed by the CeCILL 2.1 license under French law and abiding by the rules of distribution of free
 * software. You can use, modify and/ or redistribute the software under the terms of the CeCILL 2.1 license as
 * circulated by CEA, CNRS and INRIA at the following URL "https://cecill.info".
 *
 * As a counterpart to the access to the source code and rights to copy, modify and redistribute granted by the license,
 * users are provided only with a limited warranty and the software's author, the holder of the economic rights, and the
 * successive licensors have only limited liability.
 *
 * In this respect, the user's attention is drawn to the risks associated with loading, using, modifying and/or
 * developing or reproducing the software by the user in light of its specific status of free software, that may mean
 * that it is complicated to manipulate, and that also therefore means that it is reserved for developers and
 * experienced professionals having in-depth computer knowledge. Users are therefore encouraged to load and test the
 * software's suitability as regards their requirements in conditions enabling the security of their systems and/or data
 * to be ensured and, more generally, to use and operate it in the same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had knowledge of the CeCILL 2.1 license and that you
 * accept its terms.
 */
package fr.gouv.vitamui.archives.search.external.client;


import com.fasterxml.jackson.databind.JsonNode;
import fr.gouv.vitamui.archives.search.common.dto.ArchiveUnitsDto;
import fr.gouv.vitamui.archives.search.common.dto.ExportDipCriteriaDto;
import fr.gouv.vitamui.archives.search.common.dto.ReclassificationCriteriaDto;
import fr.gouv.vitamui.archives.search.common.dto.RuleSearchCriteriaDto;
import fr.gouv.vitamui.archives.search.common.dto.SearchCriteriaDto;
import fr.gouv.vitamui.archives.search.common.dto.TransferRequestDto;
import fr.gouv.vitamui.archives.search.common.dto.UnitDescriptiveMetadataDto;
import fr.gouv.vitamui.archives.search.common.rest.RestApi;
import fr.gouv.vitamui.commons.api.CommonConstants;
import fr.gouv.vitamui.commons.api.domain.PaginatedValuesDto;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.rest.client.BasePaginatingAndSortingRestClient;
import fr.gouv.vitamui.commons.rest.client.ExternalHttpContext;
import fr.gouv.vitamui.commons.vitam.api.dto.ResultsDto;
import fr.gouv.vitamui.commons.vitam.api.dto.VitamUISearchResponseDto;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Collections;
import java.util.List;


public class ArchiveSearchExternalRestClient
    extends BasePaginatingAndSortingRestClient<ArchiveUnitsDto, ExternalHttpContext> {

    private static final VitamUILogger LOGGER =
        VitamUILoggerFactory.getInstance(ArchiveSearchExternalRestClient.class);

    public ArchiveSearchExternalRestClient(final RestTemplate restTemplate, final String baseUrl) {
        super(restTemplate, baseUrl);
    }

    @Override
    protected Class<ArchiveUnitsDto> getDtoClass() {
        return ArchiveUnitsDto.class;
    }

    @Override
    protected ParameterizedTypeReference<List<ArchiveUnitsDto>> getDtoListClass() {
        return new ParameterizedTypeReference<List<ArchiveUnitsDto>>() {
        };
    }

    @Override
    protected ParameterizedTypeReference<PaginatedValuesDto<ArchiveUnitsDto>> getDtoPaginatedClass() {
        return new ParameterizedTypeReference<PaginatedValuesDto<ArchiveUnitsDto>>() {
        };
    }

    @Override
    public String getPathUrl() {
        return RestApi.ARCHIVE_SEARCH_PATH;
    }

    public ArchiveUnitsDto searchArchiveUnitsByCriteria(ExternalHttpContext context, SearchCriteriaDto query) {
        LOGGER.debug("Calling search archives units by criteria");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);

        final HttpEntity<SearchCriteriaDto> request = new HttpEntity<>(query, headers);
        final ResponseEntity<ArchiveUnitsDto> response =
            restTemplate.exchange(getUrl() + RestApi.SEARCH_PATH, HttpMethod.POST,
                request, ArchiveUnitsDto.class);
        checkResponse(response);
        return response.getBody();
    }

    public VitamUISearchResponseDto getFilingHoldingScheme(ExternalHttpContext context) {
        LOGGER.debug("Calling get filing holding scheme");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);

        final HttpEntity<Void> request = new HttpEntity<>(headers);
        final ResponseEntity<VitamUISearchResponseDto> response = restTemplate
            .exchange(getUrl() + RestApi.FILING_HOLDING_SCHEME_PATH, HttpMethod.GET, request,
                VitamUISearchResponseDto.class);
        checkResponse(response);
        return response.getBody();
    }

    protected MultiValueMap<String, String> buildSearchHeaders(final ExternalHttpContext context) {
        final MultiValueMap<String, String> headers = buildHeaders(context);
        String accessContract = null;
        if (context instanceof ExternalHttpContext) {
            final ExternalHttpContext externalCallContext = context;
            accessContract = externalCallContext.getAccessContract();
        }

        if (accessContract != null) {
            headers.put(CommonConstants.X_ACCESS_CONTRACT_ID_HEADER, Collections.singletonList(accessContract));
        }
        return headers;
    }

    public ResponseEntity<ResultsDto> findUnitById(String id, ExternalHttpContext context) {
        final UriComponentsBuilder uriBuilder =
            UriComponentsBuilder.fromHttpUrl(getUrl() + RestApi.ARCHIVE_UNIT_INFO + CommonConstants.PATH_ID);
        final HttpEntity<?> request = new HttpEntity<>(buildHeaders(context));
        return restTemplate.exchange(uriBuilder.build(id), HttpMethod.GET, request, ResultsDto.class);
    }

    public ResponseEntity<ResultsDto> findObjectById(String id, ExternalHttpContext context) {
        final UriComponentsBuilder uriBuilder =
            UriComponentsBuilder.fromHttpUrl(getUrl() + RestApi.OBJECTGROUP + CommonConstants.PATH_ID);
        final HttpEntity<?> request = new HttpEntity<>(buildHeaders(context));
        return restTemplate.exchange(uriBuilder.build(id), HttpMethod.GET, request, ResultsDto.class);

    }

    public ResponseEntity<Resource> exportCsvArchiveUnitsByCriteria(SearchCriteriaDto query,
        ExternalHttpContext context) {
        LOGGER.debug("Calling export to csv search archives units by criteria");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);

        final HttpEntity<SearchCriteriaDto> request = new HttpEntity<>(query, headers);
        final ResponseEntity<Resource> response =
            restTemplate.exchange(getUrl() + RestApi.EXPORT_CSV_SEARCH_PATH, HttpMethod.POST,
                request, Resource.class);
        return response;
    }

    public ResponseEntity<String> exportDIPCriteria(ExportDipCriteriaDto exportDipCriteriaDto,
        ExternalHttpContext context) {
        LOGGER.debug("Calling export DIP by criteria");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);
        final HttpEntity<ExportDipCriteriaDto> request = new HttpEntity<>(exportDipCriteriaDto, headers);
        final ResponseEntity<String> response =
            restTemplate.exchange(getUrl() + RestApi.EXPORT_DIP, HttpMethod.POST,
                request, String.class);
        return response;
    }

    public ResponseEntity<String> transferRequest(TransferRequestDto transferRequestDto,
        ExternalHttpContext context) {
        LOGGER.debug("Calling transfer request");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);
        final HttpEntity<TransferRequestDto> request = new HttpEntity<>(transferRequestDto, headers);
        return restTemplate.exchange(getUrl() + RestApi.TRANSFER_REQUEST, HttpMethod.POST, request, String.class);
    }

    public ResponseEntity<JsonNode> startEliminationAnalysis(ExternalHttpContext context, SearchCriteriaDto query) {
        LOGGER.debug("Calling elimination analysis by criteria");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);
        final HttpEntity<SearchCriteriaDto> request = new HttpEntity<>(query, headers);
        return restTemplate.exchange(getUrl() + RestApi.ELIMINATION_ANALYSIS, HttpMethod.POST,
            request, JsonNode.class);
    }

    public ResponseEntity<JsonNode> startEliminationAction(ExternalHttpContext context, SearchCriteriaDto query) {
        LOGGER.debug("Calling elimination action by using criteria {}", query);
        MultiValueMap<String, String> headers = buildSearchHeaders(context);
        final HttpEntity<SearchCriteriaDto> request = new HttpEntity<>(query, headers);
        return restTemplate.exchange(getUrl() + RestApi.ELIMINATION_ACTION, HttpMethod.POST,
            request, JsonNode.class);
    }

    public ResponseEntity<String> updateArchiveUnitsRules(RuleSearchCriteriaDto ruleSearchCriteriaDto,
        ExternalHttpContext context) {
        LOGGER.debug("Calling updateArchiveUnitsRules by criteria");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);
        final HttpEntity<RuleSearchCriteriaDto> request = new HttpEntity<>(ruleSearchCriteriaDto, headers);
        final ResponseEntity<String> response =
            restTemplate.exchange(getUrl() + RestApi.MASS_UPDATE_UNITS_RULES, HttpMethod.POST,
                request, String.class);
        return response;
    }

    public ResponseEntity<String> computedInheritedRules(SearchCriteriaDto searchCriteriaDto,
        ExternalHttpContext context) {
        LOGGER.debug("Calling computed inherited rules by criteria");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);
        final HttpEntity<SearchCriteriaDto> request = new HttpEntity<>(searchCriteriaDto, headers);
        final ResponseEntity<String> response =
            restTemplate.exchange(getUrl() + RestApi.COMPUTED_INHERITED_RULES, HttpMethod.POST,
                request, String.class);
        return response;
    }


    public ResponseEntity<ResultsDto> selectUnitWithInheritedRules(ExternalHttpContext context,
        SearchCriteriaDto query) {
        LOGGER.debug("Calling select Unit With Inherited Rules by criteria");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);

        final HttpEntity<SearchCriteriaDto> request = new HttpEntity<>(query, headers);
        final ResponseEntity<ResultsDto> response =
            restTemplate.exchange(getUrl() + RestApi.UNIT_WITH_INHERITED_RULES, HttpMethod.POST,
                request, ResultsDto.class);
        checkResponse(response);
        return response;
    }

    public ResponseEntity<String> reclassification(final ReclassificationCriteriaDto reclassificationCriteriaDto,
        final ExternalHttpContext context) {
        LOGGER.debug("Calling reclassification with query {} ", reclassificationCriteriaDto);
        MultiValueMap<String, String> headers = buildSearchHeaders(context);
        final HttpEntity<ReclassificationCriteriaDto> request = new HttpEntity<>(reclassificationCriteriaDto, headers);
        final ResponseEntity<String> response =
            restTemplate.exchange(getUrl() + RestApi.RECLASSIFICATION, HttpMethod.POST,
                request, String.class);
        checkResponse(response);
        return response;
    }

    public ResponseEntity<String> updateUnitById(String id, UnitDescriptiveMetadataDto unitDescriptiveMetadataDto,
        ExternalHttpContext context) {
        final UriComponentsBuilder uriBuilder =
            UriComponentsBuilder.fromHttpUrl(getUrl() + RestApi.ARCHIVE_UNIT_INFO + CommonConstants.PATH_ID);
        final HttpEntity<?> request = new HttpEntity<>(unitDescriptiveMetadataDto, buildHeaders(context));
        return restTemplate.exchange(uriBuilder.build(id), HttpMethod.PUT, request, String.class);
    }
}
