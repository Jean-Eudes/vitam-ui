/*
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2015-2020)
 * contact.vitam@culture.gouv.fr
 *
 * This software is a computer program whose purpose is to implement a digital archiving back-office system managing
 * high volumetry securely and efficiently.
 *
 * This software is governed by the CeCILL 2.1 license under French law and abiding by the rules of distribution of free
 * software. You can use, modify and/ or redistribute the software under the terms of the CeCILL 2.1 license as
 * circulated by CEA, CNRS and INRIA at the following URL "http://www.cecill.info".
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

package fr.gouv.vitamui.archives.search.external.server.rest;


import com.fasterxml.jackson.databind.JsonNode;
import fr.gouv.vitam.common.exception.InvalidParseOperationException;
import fr.gouv.vitamui.archives.search.common.dto.ArchiveUnitsDto;
import fr.gouv.vitamui.archives.search.common.dto.ExportDipCriteriaDto;
import fr.gouv.vitamui.archives.search.common.dto.RuleSearchCriteriaDto;
import fr.gouv.vitamui.archives.search.common.dto.SearchCriteriaDto;
import fr.gouv.vitamui.archives.search.common.rest.RestApi;
import fr.gouv.vitamui.archives.search.external.server.service.ArchivesSearchExternalService;
import fr.gouv.vitamui.common.security.SanityChecker;
import fr.gouv.vitamui.commons.api.CommonConstants;
import fr.gouv.vitamui.commons.api.ParameterChecker;
import fr.gouv.vitamui.commons.api.domain.ServicesData;
import fr.gouv.vitamui.commons.api.exception.InvalidSanitizeCriteriaException;
import fr.gouv.vitamui.commons.api.exception.InvalidSanitizeParameterException;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.vitam.api.dto.ResultsDto;
import fr.gouv.vitamui.commons.vitam.api.dto.VitamUISearchResponseDto;
import io.swagger.annotations.Api;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;


/**
 * UI Archive-Search External controller
 */
@Api(tags = "Archives search")
@RequestMapping(RestApi.ARCHIVE_SEARCH_PATH)
@RestController
@ResponseBody
public class ArchivesSearchExternalController {

    private static final VitamUILogger LOGGER =
        VitamUILoggerFactory.getInstance(ArchivesSearchExternalController.class);

    private final ArchivesSearchExternalService archivesSearchExternalService;

    @Autowired
    public ArchivesSearchExternalController(ArchivesSearchExternalService archivesSearchExternalService) {
        this.archivesSearchExternalService = archivesSearchExternalService;
    }

    @PostMapping(RestApi.SEARCH_PATH)
    @Secured(ServicesData.ROLE_GET_ARCHIVE)
    public ArchiveUnitsDto searchArchiveUnitsByCriteria(final @RequestBody SearchCriteriaDto query) {
        LOGGER.info("Calling search archive Units By Criteria {} ", query);
        ParameterChecker.checkParameter("The query is a mandatory parameter: ", query);
        SanityChecker.sanitizeCriteria(query);
        return archivesSearchExternalService.searchArchiveUnitsByCriteria(query);
    }

    @GetMapping(RestApi.FILING_HOLDING_SCHEME_PATH)
    @Secured(ServicesData.ROLE_GET_ARCHIVE)
    public VitamUISearchResponseDto getFillingHoldingScheme() {
        return archivesSearchExternalService.getFilingHoldingScheme();
    }

    @GetMapping(value = RestApi.DOWNLOAD_ARCHIVE_UNIT +
        CommonConstants.PATH_ID, produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    @Secured(ServicesData.ROLE_GET_ARCHIVE)
    public Mono<ResponseEntity<Resource>> downloadObjectFromUnit(final @PathVariable("id") String id,
        final @RequestParam("usage") String usage, final @RequestParam("version") Integer version) {
        LOGGER.info("Download the Archive Unit Object with id {} ", id);
        ParameterChecker.checkParameter("The Identifier is a mandatory parameter: ", id);
        return archivesSearchExternalService.downloadObjectFromUnit(id, usage, version);
    }

    @GetMapping(RestApi.ARCHIVE_UNIT_INFO + CommonConstants.PATH_ID)
    @Secured(ServicesData.ROLE_GET_ARCHIVE)
    public ResponseEntity<ResultsDto> findUnitById(final @PathVariable("id") String id)
        throws InvalidSanitizeParameterException {

        try {
            LOGGER.debug("the UA by id {} ", id);
            ParameterChecker.checkParameter("The Identifier is a mandatory parameter: ", id);
            SanityChecker.checkParameter(id);
            return archivesSearchExternalService.findUnitById(id);
        } catch (InvalidSanitizeParameterException e ) {
            LOGGER.debug("Error in checking Id : {}", e.getMessage());
            throw new InvalidSanitizeParameterException(e);
        }

    }

    @GetMapping(RestApi.OBJECTGROUP + CommonConstants.PATH_ID)
    @Secured(ServicesData.ROLE_GET_ARCHIVE)
    public ResponseEntity<ResultsDto> findObjectById(final @PathVariable("id") String id)
        throws InvalidSanitizeParameterException {

        try {
           //LOGGER.debug("Find a ObjectGroup by id {} ", id);
           ParameterChecker.checkParameter("The Identifier is a mandatory parameter: ", id);
           SanityChecker.checkParameter(id);
           return archivesSearchExternalService.findObjectById(id);
       } catch (InvalidSanitizeParameterException e) {
            LOGGER.debug("Error in checking Id : {}", e.getMessage());
           throw new InvalidSanitizeParameterException(e);
       }

    }

    @PostMapping(RestApi.EXPORT_CSV_SEARCH_PATH)
    @Secured(ServicesData.ROLE_GET_ARCHIVE)
    public Resource exportCsvArchiveUnitsByCriteria(final @RequestBody SearchCriteriaDto query) throws
        InvalidSanitizeCriteriaException {

        try {
            LOGGER.info("Calling export to csv search archive Units By Criteria {} ", query);
            ParameterChecker.checkParameter("The query is a mandatory parameter: ", query);
            SanityChecker.sanitizeCriteria(query);
            return archivesSearchExternalService.exportCsvArchiveUnitsByCriteria(query);
        } catch(InvalidSanitizeCriteriaException e) {
            LOGGER.debug("error with export CSV criteria : {}", e.getMessage());
            throw new InvalidSanitizeCriteriaException("error with export CSV criteria" , e);
        }

    }

    @PostMapping(RestApi.EXPORT_DIP)
    @Secured(ServicesData.ROLE_EXPORT_DIP)
    public String exportDIPByCriteria(final @RequestBody ExportDipCriteriaDto exportDipCriteriaDto) throws InvalidSanitizeCriteriaException{

        try {
            LOGGER.info("Calling export DIP By Criteria {} ", exportDipCriteriaDto);
            ParameterChecker.checkParameter("The query is a mandatory parameter: ", exportDipCriteriaDto);
            SanityChecker.sanitizeCriteria(exportDipCriteriaDto);
            return archivesSearchExternalService.exportDIPByCriteria(exportDipCriteriaDto);
        } catch (InvalidSanitizeCriteriaException e) {
            LOGGER.debug("error with export DIP criteria : {}", e.getMessage());
            throw new InvalidSanitizeCriteriaException("error with export DIP criteria" , e);
        }

    }

    @PostMapping(RestApi.ELIMINATION_ANALYSIS)
    @Secured(ServicesData.ROLE_ELIMINATION)
    public ResponseEntity<JsonNode> startEliminationAnalysis(final @RequestBody SearchCriteriaDto query) {
        LOGGER.info("Calling elimination analysis by criteria {} ", query);
        ParameterChecker.checkParameter("The query is a mandatory parameter: ", query);
        SanityChecker.sanitizeCriteria(query);
        return archivesSearchExternalService.startEliminationAnalysis(query);
    }

    @PostMapping(RestApi.ELIMINATION_ACTION)
    @Secured(ServicesData.ROLE_ELIMINATION)
    public ResponseEntity<JsonNode> startEliminationAction(final @RequestBody SearchCriteriaDto query) {

        try {
            LOGGER.info("Calling elimination action by criteria {} ", query);
            ParameterChecker.checkParameter("The query is a mandatory parameter: ", query);
            SanityChecker.sanitizeCriteria(query);
            return archivesSearchExternalService.startEliminationAction(query);
        } catch (InvalidSanitizeCriteriaException e) {
        LOGGER.debug("error with elimination action criteria : {}", e.getMessage());
        throw new InvalidSanitizeCriteriaException("error with elimination action criteria" , e);
    }
    }

    @PostMapping(RestApi.MASS_UPDATE_UNITS_RULES)
    @Secured(ServicesData.ROLE_UPDATE_MANAGEMENT_RULES)
    public String updateArchiveUnitsRules(final @RequestBody RuleSearchCriteriaDto ruleSearchCriteriaDto) {
        LOGGER.info("Calling Update Archive Units Rules By Criteria {} ", ruleSearchCriteriaDto);
        ParameterChecker.checkParameter("The query is a mandatory parameter: ", ruleSearchCriteriaDto);
        SanityChecker.sanitizeCriteria(ruleSearchCriteriaDto);
        return archivesSearchExternalService.updateArchiveUnitsRules(ruleSearchCriteriaDto);
    }
}
