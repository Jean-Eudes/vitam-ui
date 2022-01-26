/*
Copyright © CINES - Centre Informatique National pour l'Enseignement Supérieur (2021)

[dad@cines.fr]

This software is a computer program whose purpose is to provide
a web application to create, edit, import and export archive
profiles based on the french SEDA standard
(https://redirect.francearchives.fr/seda/).


This software is governed by the CeCILL-C  license under French law and
abiding by the rules of distribution of free software.  You can  use,
modify and/ or redistribute the software under the terms of the CeCILL-C
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info".

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability.

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or
data to be ensured and,  more generally, to use and operate it in the
same conditions as regards security.

The fact that you are presently reading this means that you have had
knowledge of the CeCILL-C license and that you accept its terms.
*/

package fr.gouv.vitamui.pastis.client;

import fr.gouv.vitamui.commons.api.domain.PaginatedValuesDto;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.rest.client.BasePaginatingAndSortingRestClient;
import fr.gouv.vitamui.commons.rest.client.ExternalHttpContext;
import fr.gouv.vitamui.pastis.common.dto.ElementProperties;
import fr.gouv.vitamui.pastis.common.dto.profiles.Notice;
import fr.gouv.vitamui.pastis.common.dto.profiles.ProfileNotice;
import fr.gouv.vitamui.pastis.common.dto.profiles.ProfileResponse;
import fr.gouv.vitamui.pastis.common.rest.RestApi;
import fr.gouv.vitamui.pastis.common.util.FileSystemResource;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.List;

public class PastisTransformationRestClient
    extends BasePaginatingAndSortingRestClient<ProfileResponse, ExternalHttpContext> {

    private static final VitamUILogger LOGGER =
        VitamUILoggerFactory.getInstance(PastisTransformationRestClient.class);

    public PastisTransformationRestClient(RestTemplate restTemplate,
        String baseUrl) {
        super(restTemplate, baseUrl);
    }

    @Override
    protected Class<ProfileResponse> getDtoClass() {
        return ProfileResponse.class;
    }

    @Override
    protected ParameterizedTypeReference<List<ProfileResponse>> getDtoListClass() {
        return new ParameterizedTypeReference<List<ProfileResponse>>() {
        };
    }

    @Override
    protected ParameterizedTypeReference<PaginatedValuesDto<ProfileResponse>> getDtoPaginatedClass() {
        return new ParameterizedTypeReference<PaginatedValuesDto<ProfileResponse>>() {
        };
    }

    @Override
    public String getPathUrl() {
        return RestApi.PASTIS;
    }

    public ResponseEntity<ProfileResponse> loadProfile(Notice notice, ExternalHttpContext context)
        throws IOException {
        LOGGER.debug("Transform profile");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);
        final HttpEntity<Notice> request = new HttpEntity<>(notice, headers);
        final ResponseEntity<ProfileResponse> response =
            restTemplate.exchange(getUrl() + RestApi.PASTIS_TRANSFORM_PROFILE, HttpMethod.POST,
                request, ProfileResponse.class);
        return response;
    }

    public ResponseEntity<ProfileResponse> loadProfileFromFile(MultipartFile file, ExternalHttpContext context)
        throws IOException {
        LOGGER.debug("Upload profile");
        final UriComponentsBuilder uriBuilder =
            UriComponentsBuilder.fromHttpUrl(getUrl() + RestApi.PASTIS_UPLOAD_PROFILE);
        MultiValueMap<String, Object> bodyMap = new LinkedMultiValueMap<>();
        bodyMap.add("file", new FileSystemResource(file.getBytes(), file.getOriginalFilename()));
        final HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(bodyMap, buildHeaders(context));
        return restTemplate.exchange(getUrl() + RestApi.PASTIS_UPLOAD_PROFILE,
            HttpMethod.POST,
            request,
            ProfileResponse.class);
    }

    public ResponseEntity<String> getArchiveProfile(final ElementProperties json, ExternalHttpContext context)
        throws IOException {
        LOGGER.debug("Download archive profile");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);
        final HttpEntity<ElementProperties> request = new HttpEntity<>(json, headers);
        final ResponseEntity<String> response =
            restTemplate.exchange(getUrl() + RestApi.PASTIS_DOWNLOAD_PA, HttpMethod.POST,
                request, String.class);
        return response;
    }

    public ResponseEntity<String> getArchiveUnitProfile(final ProfileNotice json, ExternalHttpContext context)
        throws IOException {
        LOGGER.debug("Download Arichivale unit profile");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);
        final HttpEntity<ProfileNotice> request = new HttpEntity<>(json, headers);
        final ResponseEntity<String> response =
            restTemplate.exchange(getUrl() + RestApi.PASTIS_DOWNLOAD_PUA, HttpMethod.POST,
                request, String.class);
        return response;
    }


    public ResponseEntity<ElementProperties> loadProfilePA(Resource resource, ExternalHttpContext context)
        throws IOException {
        LOGGER.debug("Upload profile");
        MultiValueMap<String, Object> bodyMap = new LinkedMultiValueMap<>();
        bodyMap.add("file", new FileSystemResource(resource.getInputStream().readAllBytes(), "test_eeee.rng"));
        final HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(bodyMap, buildHeaders(context));
        return restTemplate.exchange(getUrl() + RestApi.PASTIS_TRANSFORM_PROFILE_PA,
            HttpMethod.POST,
            request,
            ElementProperties.class);
    }

    public ResponseEntity<ProfileResponse> createProfile(String profileType, ExternalHttpContext context)
        throws IOException {
        LOGGER.debug("Transform profile");
        MultiValueMap<String, String> headers = buildSearchHeaders(context);
        final HttpEntity<Notice> request = new HttpEntity<>(headers);
        final ResponseEntity<ProfileResponse> response =
            restTemplate.exchange(getUrl() + RestApi.PASTIS_CREATE_PROFILE + "?type=" + profileType, HttpMethod.GET,
                request, ProfileResponse.class);
        return response;
    }
}