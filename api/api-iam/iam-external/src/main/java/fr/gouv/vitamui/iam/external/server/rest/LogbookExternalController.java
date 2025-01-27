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
package fr.gouv.vitamui.iam.external.server.rest;

import com.fasterxml.jackson.databind.JsonNode;
import fr.gouv.vitam.common.exception.InvalidParseOperationException;
import fr.gouv.vitam.common.exception.VitamClientException;
import fr.gouv.vitamui.common.security.SanityChecker;
import fr.gouv.vitamui.commons.api.CommonConstants;
import fr.gouv.vitamui.commons.api.ParameterChecker;
import fr.gouv.vitamui.commons.api.domain.ServicesData;
import fr.gouv.vitamui.commons.api.exception.PreconditionFailedException;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.rest.util.RestUtils;
import fr.gouv.vitamui.commons.vitam.api.dto.LogbookLifeCycleResponseDto;
import fr.gouv.vitamui.commons.vitam.api.dto.LogbookOperationsResponseDto;
import fr.gouv.vitamui.iam.external.server.service.LogbookExternalService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

/**
 * UI logbook controller.
 *
 *
 */
@Api(tags = "logbooks")
@RequestMapping(CommonConstants.API_VERSION_1)
@RestController
@ResponseBody
public class LogbookExternalController {

    private static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(LogbookExternalController.class);

    private final LogbookExternalService logbookExternalService;

    @Autowired
    public LogbookExternalController(final LogbookExternalService logbookExternalService) {
        this.logbookExternalService = logbookExternalService;
    }

    @ApiOperation(value = "Get operation by id")
    @GetMapping(CommonConstants.LOGBOOK_OPERATION_BY_ID_PATH)
    @ResponseStatus(HttpStatus.OK)
    public LogbookOperationsResponseDto findOperationByUnitId(@PathVariable final String id)
        throws InvalidParseOperationException, PreconditionFailedException {

        SanityChecker.checkSecureParameter(id);
        ParameterChecker.checkParameter("Identifier is mandatory : ", id);
        return logbookExternalService.findOperationByUnitId(id);
    }

    @ApiOperation(value = "Get logbook unit lifecycle by archive unit id")
    @GetMapping(CommonConstants.LOGBOOK_UNIT_LYFECYCLES_PATH)
    @ResponseStatus(HttpStatus.OK)
    public LogbookLifeCycleResponseDto findUnitLifeCyclesByUnitId(@PathVariable final String id)
        throws InvalidParseOperationException, PreconditionFailedException {

        SanityChecker.checkSecureParameter(id);
        ParameterChecker.checkParameter("Identifier is mandatory : ", id);
        return logbookExternalService.findUnitLifeCyclesByUnitId(id);
    }

    @ApiOperation(value = "Get logbook object lifecycle by archive unit id")
    @GetMapping(CommonConstants.LOGBOOK_OBJECT_LYFECYCLES_PATH)
    @ResponseStatus(HttpStatus.OK)
    public LogbookLifeCycleResponseDto findObjectGroupLifeCyclesByUnitId(@PathVariable final String id)
        throws InvalidParseOperationException, PreconditionFailedException {

        SanityChecker.checkSecureParameter(id);
        ParameterChecker.checkParameter("Identifier is mandatory : ", id);
        return logbookExternalService.findObjectGroupLifeCyclesByUnitId(id);
    }

    @ApiOperation(value = "Get logbook operations by json select")
    @Secured({ServicesData.ROLE_LOGBOOKS})
    @PostMapping(value = CommonConstants.LOGBOOK_OPERATIONS_PATH)
    public LogbookOperationsResponseDto findOperations(@RequestBody final JsonNode select) throws VitamClientException {
        return logbookExternalService.findOperations(select);
    }

    @ApiOperation(value = "Download the manifest for a given operation")
    @GetMapping(value = CommonConstants.LOGBOOK_DOWNLOAD_MANIFEST_PATH)
    @Secured(ServicesData.ROLE_LOGBOOKS)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<Resource> downloadManifest(@PathVariable final String id)
        throws InvalidParseOperationException, PreconditionFailedException {

        ParameterChecker.checkParameter("Identifier is mandatory : ", id);
        SanityChecker.checkSecureParameter(id);
        LOGGER.debug("Download the manifest for the Vitam operation : {}", id);
        final ResponseEntity<Resource> response = logbookExternalService.downloadManifest(id);
        return RestUtils.buildFileResponse(response, Optional.empty(), Optional.empty());
    }

    @ApiOperation(value = "Download the ATR file for a given operation")
    @GetMapping(value = CommonConstants.LOGBOOK_DOWNLOAD_ATR_PATH)
    @Secured(ServicesData.ROLE_LOGBOOKS)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<Resource> downloadAtr(@PathVariable final String id) throws InvalidParseOperationException,
        PreconditionFailedException {

        ParameterChecker.checkParameter("Identifier is mandatory : ", id);
        SanityChecker.checkSecureParameter(id);
        LOGGER.debug("Download the ATR file for the Vitam operation : {}", id);
        final ResponseEntity<Resource> response = logbookExternalService.downloadAtr(id);
        return RestUtils.buildFileResponse(response, Optional.empty(), Optional.empty());
    }

    @ApiOperation(value = "Download the report file for a given operation")
    @GetMapping(value = CommonConstants.LOGBOOK_DOWNLOAD_REPORT_PATH, produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    @Secured(ServicesData.ROLE_LOGBOOKS)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<Resource> downloadReport(@PathVariable final String id, @PathVariable final String downloadType)
        throws InvalidParseOperationException, PreconditionFailedException {

        ParameterChecker.checkParameter("The Identifier and the download type are mandatory parameters: ", id, downloadType);
        SanityChecker.checkSecureParameter(id, downloadType);
        LOGGER.debug("Download the report file for the Vitam operation : {} with download type : {}", id, downloadType);
        ResponseEntity<Resource> responseResource = logbookExternalService.downloadReport(id, downloadType).block();
        return RestUtils.buildFileResponse(responseResource, Optional.empty(), Optional.empty());
    }

}
