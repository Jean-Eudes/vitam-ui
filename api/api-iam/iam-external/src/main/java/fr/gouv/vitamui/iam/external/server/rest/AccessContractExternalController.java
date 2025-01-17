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

import fr.gouv.vitamui.commons.api.CommonConstants;
import fr.gouv.vitamui.commons.api.domain.AccessContractsDto;
import fr.gouv.vitamui.commons.api.domain.ServicesData;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.iam.external.server.service.AccessContractExternalService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Controller for Access contracts.
 */
@RestController
@RequestMapping(CommonConstants.API_VERSION_1)
@Api(tags = "accesscontracts", value = "Access contact", description = "Access contract Management")
public class AccessContractExternalController {

    static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(AccessContractExternalController.class);

    private final AccessContractExternalService accessContractExternalService;

    @Autowired
    public AccessContractExternalController(
        AccessContractExternalService accessContractExternalService) {
        this.accessContractExternalService = accessContractExternalService;
    }

    @ApiOperation(value = "Get all access contracts")
    @GetMapping("/accesscontracts")
    @Secured(ServicesData.ROLE_GET_ACCESS_CONTRACT_EXTERNAL_PARAM_PROFILE)
    public List<AccessContractsDto> getAll() {
        return accessContractExternalService.getAll();
    }

    @ApiOperation(value = "Get access contract by ID")
    @GetMapping(path = "/accesscontracts/{identifier:.+}")
    @Secured(ServicesData.ROLE_GET_ACCESS_CONTRACTS)
    public AccessContractsDto getById(final @PathVariable("identifier") String identifier) throws
        UnsupportedEncodingException {
        LOGGER.debug("get access contract by id {} / {}", identifier, URLEncoder.encode(identifier, StandardCharsets.UTF_8.toString()));
        return accessContractExternalService.getAccessContractById(URLEncoder.encode(identifier, StandardCharsets.UTF_8.toString()));
    }

}
