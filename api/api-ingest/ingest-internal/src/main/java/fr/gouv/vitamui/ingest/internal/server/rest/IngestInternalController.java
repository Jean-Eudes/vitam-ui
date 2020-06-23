/*
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2015-2020)
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
package fr.gouv.vitamui.ingest.internal.server.rest;

import fr.gouv.vitam.common.model.RequestResponseOK;
import fr.gouv.vitam.ingest.external.api.exception.IngestExternalException;
import fr.gouv.vitamui.commons.api.CommonConstants;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.ingest.common.rest.RestApi;
import fr.gouv.vitamui.ingest.internal.server.service.IngestInternalService;
import io.swagger.annotations.Api;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping(RestApi.V1_INGEST)
@Getter
@Setter
@Api(tags = "ingest", value = "Ingest an SIP", description = "Ingest an SIP")
public class IngestInternalController {

    private static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(IngestInternalController.class);

    private IngestInternalService ingestInternalService;

    @Autowired
    public IngestInternalController(final IngestInternalService ingestInternalService) {
        this.ingestInternalService = ingestInternalService;
    }

    @GetMapping
    public String ingest() {
        return ingestInternalService.ingest();
    }

    @PostMapping(value = CommonConstants.INGEST_UPLOAD, consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public RequestResponseOK upload(
        @RequestHeader(value = CommonConstants.X_ACTION) final String action,
        @RequestHeader(value = CommonConstants.X_CONTEXT_ID) final String contextId,
        @RequestParam(CommonConstants.MULTIPART_FILE_PARAM_NAME) final MultipartFile path)
        throws IngestExternalException {
        LOGGER.debug("[Internal] upload file : {}", path.getOriginalFilename());
        return ingestInternalService.upload(path, contextId, action);
    }
}
