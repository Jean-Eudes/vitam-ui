/*
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2015-2021)
 *
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

package fr.gouv.vitamui.referential.external.server.service;

import fr.gouv.vitam.common.model.ProcessQuery;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.rest.client.BasePaginatingAndSortingRestClient;
import fr.gouv.vitamui.commons.rest.client.InternalHttpContext;
import fr.gouv.vitamui.iam.security.client.AbstractResourceClientService;
import fr.gouv.vitamui.iam.security.service.ExternalSecurityService;
import fr.gouv.vitamui.referential.common.dto.ProcessDetailDto;
import fr.gouv.vitamui.referential.internal.client.LogbookManagementOperationInternalRestClient;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Getter
@Setter
@Service
public class LogbookManagementOperationExternalService extends AbstractResourceClientService<ProcessDetailDto, ProcessDetailDto> {

    private static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(LogbookManagementOperationExternalService.class);

    private LogbookManagementOperationInternalRestClient logbookManagementOperationInternalRestClient;

    @Autowired
    public LogbookManagementOperationExternalService(ExternalSecurityService externalSecurityService, LogbookManagementOperationInternalRestClient logbookManagementOperationInternalRestClient) {
        super(externalSecurityService);
        this.logbookManagementOperationInternalRestClient = logbookManagementOperationInternalRestClient;
    }

    @Override
    protected BasePaginatingAndSortingRestClient<ProcessDetailDto, InternalHttpContext> getClient() {
        return logbookManagementOperationInternalRestClient;
    }

    public ProcessDetailDto searchOperationsDetails(ProcessQuery processQuery) {
        LOGGER.debug("Get all Operations details with processQuery = {} ", processQuery);
        return logbookManagementOperationInternalRestClient.searchOperationsDetails(getInternalHttpContext(), processQuery);
    }

    public ProcessDetailDto cancelOperationProcessExecution(String operationId) {
        LOGGER.debug("Cancel the operation Id= {} ", operationId);
        return logbookManagementOperationInternalRestClient.cancelOperationProcessExecution(getInternalHttpContext(), operationId);
    }

    public ProcessDetailDto updateOperationActionProcess(String operationId, String actionId) {
        LOGGER.debug("Update operation Id= {} with the action Id= {}",operationId, actionId);
        return logbookManagementOperationInternalRestClient.updateOperationActionProcess(getInternalHttpContext(), actionId, operationId);
    }


}
