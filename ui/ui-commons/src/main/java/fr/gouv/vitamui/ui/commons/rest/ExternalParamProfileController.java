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
package fr.gouv.vitamui.ui.commons.rest;

import fr.gouv.vitam.common.exception.InvalidParseOperationException;
import fr.gouv.vitamui.common.security.SanityChecker;
import fr.gouv.vitamui.commons.api.CommonConstants;
import fr.gouv.vitamui.commons.api.ParameterChecker;
import fr.gouv.vitamui.commons.api.domain.DirectionDto;
import fr.gouv.vitamui.commons.api.domain.ExternalParamProfileDto;
import fr.gouv.vitamui.commons.api.domain.PaginatedValuesDto;
import fr.gouv.vitamui.commons.api.exception.PreconditionFailedException;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.api.utils.EnumUtils;
import fr.gouv.vitamui.commons.rest.AbstractUiRestController;
import fr.gouv.vitamui.commons.rest.util.RestUtils;
import fr.gouv.vitamui.commons.vitam.api.dto.LogbookOperationsResponseDto;
import fr.gouv.vitamui.iam.common.dto.common.EmbeddedOptions;
import fr.gouv.vitamui.ui.commons.service.ExternalParamProfileService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.Produces;
import java.util.Map;
import java.util.Optional;

@Api(tags = "externalparamprofile")
@RequestMapping("${ui-prefix}/externalparamprofile")
@RestController
@ResponseBody
public class ExternalParamProfileController extends AbstractUiRestController {

    protected final ExternalParamProfileService service;

    private static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(ExternalParamProfileController.class);

    @Autowired
    public ExternalParamProfileController(final ExternalParamProfileService service) {
        this.service = service;
    }


    @ApiOperation(value = "Get one external param profile")
    @GetMapping(CommonConstants.PATH_ID)
    @Produces("application/json")
    @ResponseStatus(HttpStatus.OK)
    public ExternalParamProfileDto getOne(final @PathVariable String id) throws InvalidParseOperationException,
        PreconditionFailedException {

        SanityChecker.checkSecureParameter(id);
        LOGGER.debug("get external param profile's profile with id :{}", id);
        return service.getOne(buildUiHttpContext(), id);
    }

    @ApiOperation(value = "Create external parameter profile")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ExternalParamProfileDto create(@RequestBody final ExternalParamProfileDto entityDto)
        throws InvalidParseOperationException, PreconditionFailedException {

        SanityChecker.sanitizeCriteria(entityDto);
        LOGGER.debug("create class={}", entityDto.getClass().getName());
        return service.create(buildUiHttpContext(), entityDto);
    }

    @ApiOperation(value = "Get all external param profiles paginated")
    @GetMapping(params = {"page", "size"})
    @ResponseStatus(HttpStatus.OK)
    public PaginatedValuesDto<ExternalParamProfileDto> getAllPaginated(@RequestParam final Integer page,
        @RequestParam final Integer size,
        @RequestParam final Optional<String> criteria, @RequestParam final Optional<String> orderBy,
        @RequestParam final Optional<DirectionDto> direction,
        @ApiParam(defaultValue = "ALL") @RequestParam final Optional<String> embedded)
        throws InvalidParseOperationException, PreconditionFailedException {

        SanityChecker.sanitizeCriteria(criteria);
        if(orderBy.isPresent()) {
            SanityChecker.checkSecureParameter(orderBy.get());
        }
        EnumUtils.checkValidEnum(EmbeddedOptions.class, embedded);
        LOGGER
            .debug("getAllPaginated page={}, size={}, criteria={}, orderBy={}, ascendant={}, embedded = {}", page, size,
                criteria, orderBy, direction,
                embedded);
        return service.getAllPaginated(page, size, criteria, orderBy, direction, embedded, buildUiHttpContext());
    }

    @ApiOperation(value = "get history by external parameter profile profile's id")
    @GetMapping(CommonConstants.PATH_LOGBOOK)
    public LogbookOperationsResponseDto findHistoryById(final @PathVariable String id)
        throws InvalidParseOperationException, PreconditionFailedException {

        ParameterChecker.checkParameter("The Identifier is a mandatory parameter: ", id);
        SanityChecker.checkSecureParameter(id);
        LOGGER.debug("get logbook for external parameter profile's profile with id :{}", id);
        return service.findHistoryById(buildUiHttpContext(), id);
    }

    @PatchMapping(value = CommonConstants.PATH_ME)
    @ApiOperation(value = "Update partially entity")
    @ResponseStatus(HttpStatus.OK)
    public ExternalParamProfileDto patch(@RequestBody final Map<String, Object> externalParamProfile)
        throws InvalidParseOperationException, PreconditionFailedException {

        SanityChecker.sanitizeCriteria(externalParamProfile);
        LOGGER.debug("Update partially provider with partialDto={}", externalParamProfile);
        return service.patch(buildUiHttpContext(), externalParamProfile, externalParamProfile.get("id").toString());
    }

    @ApiOperation(value = "Check entity exists by criteria")
    @RequestMapping(path = CommonConstants.PATH_CHECK, method = RequestMethod.HEAD)
    public ResponseEntity<Void> checkExist(@RequestParam final String criteria) throws InvalidParseOperationException,
        PreconditionFailedException {
        SanityChecker.sanitizeCriteria(Optional.of(criteria));
        LOGGER.debug("check exists criteria={}", criteria);
        final boolean exist = service.checkExist(buildUiHttpContext(), criteria);
        LOGGER.debug("reponse value={}", exist);
        return RestUtils.buildBooleanResponse(exist);
    }
}
