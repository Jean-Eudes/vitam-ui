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
package fr.gouv.vitamui.referential.external.server.rest;

import fr.gouv.vitamui.commons.api.domain.PaginatedValuesDto;
import fr.gouv.vitamui.commons.api.domain.ServicesData;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.referential.common.dto.AccessionRegisterDetailDto;
import fr.gouv.vitamui.referential.common.rest.RestApi;
import fr.gouv.vitamui.referential.external.server.service.AccessionRegisterDetailExternalService;
import fr.gouv.vitamui.referential.external.server.service.AccessionRegisterSummaryExternalService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.ResultActions;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@WebMvcTest(controllers = { AccessionRegisterExternalController.class })
class AccessionRegisterExternalControllerTest extends ApiReferentialControllerTest<AccessionRegisterDetailDto> {

    @MockBean
    private AccessionRegisterDetailExternalService detailExternalService;

    @MockBean
    private AccessionRegisterSummaryExternalService summaryExternalService;

    @Test
    void should_call_the_corresponding_service_once_when_paginated_api_is_called() throws Exception {
        //Given // When
        ResultActions resultActions = testGetPaginatedEntities("/details", getHeaders());

        //Then
        resultActions.andExpect(status().isOk());
        verify(detailExternalService, times(1)).getAllPaginated(any(), any(), any(), any(), any());
    }

    @Override
    protected AccessionRegisterDetailDto buildDto() {
        return new AccessionRegisterDetailDto();
    }

    @Override
    protected VitamUILogger getLog() {
        return VitamUILoggerFactory.getInstance(AccessionRegisterExternalController.class);
    }

    @Override
    protected void preparedServices() {
        PaginatedValuesDto<AccessionRegisterDetailDto> response = new PaginatedValuesDto<>();
        doReturn(response).when(detailExternalService).getAllPaginated(any(), any(), any(), any(), any());
    }

    @Override
    protected String getRessourcePrefix() {
        return RestApi.ACCESSION_REGISTER_URL;
    }

    @Override
    protected String[] getServices() {
        return new String[] { ServicesData.ROLE_GET_ACCESSION_REGISTER_DETAIL};
    }

    @Override
    protected Class<AccessionRegisterDetailDto> getDtoClass() {
        return AccessionRegisterDetailDto.class;
    }

}
