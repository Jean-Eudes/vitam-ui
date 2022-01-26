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

package fr.gouv.vitamui.pastis.standalone.controller;

import fr.gouv.vitamui.pastis.common.dto.ElementProperties;
import fr.gouv.vitamui.pastis.common.dto.profiles.Notice;
import fr.gouv.vitamui.pastis.common.dto.profiles.ProfileNotice;
import fr.gouv.vitamui.pastis.common.dto.profiles.ProfileResponse;
import fr.gouv.vitamui.pastis.common.rest.RestApi;
import fr.gouv.vitamui.pastis.server.service.PastisService;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.annotations.servers.ServerVariable;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;


@OpenAPIDefinition(tags = {@Tag(name = "pastis")},
    info = @Info(title = "Pastis Rest Api", description = ""),
    servers = {@Server(url = "localhost",
        variables = {@ServerVariable(name = "scheme", allowableValues = {"https", "http"}, defaultValue = "http"),
            @ServerVariable(name = "port", description = "Api port", defaultValue = "8096")})})
@RestController
class PastisController {

    private static final Logger LOGGER = LoggerFactory.getLogger(PastisController.class);

    private static final String APPLICATION_JSON_UTF8 = "application/json; charset=utf-8";

    private final PastisService profileService;

    @Autowired
    public PastisController(final PastisService profileService) {
        this.profileService = profileService;
    }

    @Operation(summary = "Retrieve RNG representation of the JSON structure",
        description = "Retrieve RNG representation of the JSON structure of archive profile",
        tags = {"pastis"})
    @RequestMapping(value = RestApi.PASTIS_DOWNLOAD_PA, method = RequestMethod.POST, consumes = APPLICATION_JSON_UTF8, produces = MediaType.APPLICATION_XML_VALUE)
    ResponseEntity<String> getArchiveProfile(@RequestBody final ElementProperties json) throws IOException {
        String pa = profileService.getArchiveProfile(json);
        if (pa != null) {
            return ResponseEntity.ok(pa);
        } else {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Operation(summary = "Retrieve JSON representation of archive unit profile",
        description = "Retrieve JSON representation of archive unit profile",
        tags = {"pastis"})
    @RequestMapping(value = RestApi.PASTIS_DOWNLOAD_PUA, method = RequestMethod.POST, consumes = APPLICATION_JSON_UTF8, produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<String> getArchiveUnitProfile(@RequestBody final ProfileNotice json) throws IOException {
        String pua = profileService.getArchiveUnitProfile(json);
        if (pua != null) {
            return ResponseEntity.ok(pua);
        } else {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @Operation(summary = "Retrieve JSON representation of the RNG structure",
        description = "Retrieve JSON representation of the RNG structure",
        tags = {"pastis"})
    @RequestMapping(value = RestApi.PASTIS_CREATE_PROFILE, method = RequestMethod.GET)
    ResponseEntity<ProfileResponse> createProfile(@RequestParam(name = "type") String profileType)
        throws URISyntaxException, IOException {
        ProfileResponse profileResponse = profileService.createProfile(profileType);
        if (profileResponse != null) {
            return ResponseEntity.ok(profileResponse);
        } else {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @RequestMapping(value = RestApi.PASTIS_GET_PROFILE_FILE, method = RequestMethod.GET)
    ResponseEntity<Resource> getFile(@RequestParam(name = "name") String filename) {
        Resource resource = profileService.getFile(filename);
        if (resource != null) {
            return ResponseEntity.ok(resource);
        } else {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Operation(summary = "Transform profile JSON representation from Notice",
        description = "Transform profile JSON representation from Notice",
        tags = {"pastis"})
    @RequestMapping(value = RestApi.PASTIS_TRANSFORM_PROFILE, method = RequestMethod.POST)
    ResponseEntity<ProfileResponse> loadProfile(@RequestBody final Notice notice)
        throws IOException {
        ProfileResponse profileResponse = profileService.loadProfile(notice);
        if (profileResponse != null) {
            return ResponseEntity.ok(profileResponse);
        } else {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Operation(summary = "Upload profile PA or PUA",
        description = "Upload profile PA or PUA",
        tags = {"pastis"})
    @RequestMapping(value = RestApi.PASTIS_UPLOAD_PROFILE, method = RequestMethod.POST,
        consumes = "multipart/form-data", produces = "application/json")
    ResponseEntity<ProfileResponse> loadProfileFromFile(@RequestParam MultipartFile file) {
        ProfileResponse profileResponse = profileService.loadProfileFromFile(file);
        if (profileResponse != null) {
            return ResponseEntity.ok(profileResponse);
        } else {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Operation(summary = "Retrieve all profiles PA and PUA",
        description = "Retrieve all profiles PA and PUA",
        tags = {"pastis"})
    @RequestMapping(value = RestApi.PASTIS_GET_ALL_PROFILES, method = RequestMethod.GET)
    ResponseEntity<List<Notice>> getFiles() throws IOException {
        List<Notice> notices = profileService.getFiles();
        if (notices != null) {
            return ResponseEntity.ok(notices);
        } else {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}