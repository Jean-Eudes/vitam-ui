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

package fr.gouv.vitamui.collect.rest;

import fr.gouv.vitam.common.exception.InvalidParseOperationException;
import fr.gouv.vitamui.collect.common.dto.ProjectDto;
import fr.gouv.vitamui.collect.service.CollectService;
import fr.gouv.vitamui.common.security.SanityChecker;
import fr.gouv.vitamui.commons.api.domain.DirectionDto;
import fr.gouv.vitamui.commons.api.domain.PaginatedValuesDto;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.rest.AbstractUiRestController;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import java.util.Optional;


@Api(tags = "Collect")
@RestController
@RequestMapping("${ui-collect.prefix}/project")
@Consumes("application/json")
@Produces("application/json")
public class ProjectController extends AbstractUiRestController {

    static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(AbstractUiRestController.class);

    private final CollectService collectService;

    @Autowired
    public ProjectController(final CollectService service) {
        this.collectService = service;
    }

    @ApiOperation(value = "Get projects paginated")
    @GetMapping(params = {"page", "size"})
    @ResponseStatus(HttpStatus.OK)
    public PaginatedValuesDto<ProjectDto> getAllProjectsPaginated(@RequestParam final Integer page,
        @RequestParam final Integer size,
        @RequestParam final Optional<String> criteria, @RequestParam final Optional<String> orderBy,
        @RequestParam final Optional<DirectionDto> direction) throws InvalidParseOperationException {
        SanityChecker.sanitizeCriteria(criteria);
        LOGGER.debug("getAllProjectsPaginated page={}, size={}, criteria={}, orderBy={}, ascendant={}", page, size, criteria,
            orderBy, direction);
        return collectService.getAllProjectsPaginated(buildUiHttpContext(), page, size, criteria, orderBy, direction);
    }

    @ApiOperation(value = "Create new collect project")
    @PostMapping
    public ProjectDto createProject(@RequestBody ProjectDto projectDto) throws InvalidParseOperationException {
        SanityChecker.sanitizeCriteria(projectDto);
        return collectService.createProject(buildUiHttpContext(), projectDto);
    }

}
