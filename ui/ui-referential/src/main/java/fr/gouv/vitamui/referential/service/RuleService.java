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
package fr.gouv.vitamui.referential.service;

import com.fasterxml.jackson.databind.JsonNode;
import fr.gouv.vitamui.commons.api.domain.DirectionDto;
import fr.gouv.vitamui.commons.api.domain.PaginatedValuesDto;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.rest.client.BasePaginatingAndSortingRestClient;
import fr.gouv.vitamui.commons.rest.client.ExternalHttpContext;
import fr.gouv.vitamui.commons.rest.dto.RuleDto;
import fr.gouv.vitamui.referential.external.client.RuleExternalRestClient;
import fr.gouv.vitamui.referential.external.client.RuleExternalWebClient;
import fr.gouv.vitamui.ui.commons.service.AbstractPaginateService;
import fr.gouv.vitamui.ui.commons.service.CommonService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;

@Deprecated(since = "5.0.2", forRemoval = true)
@Service
public class RuleService extends AbstractPaginateService<RuleDto> {
    static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(RuleService.class);

    private RuleExternalRestClient client;

    private RuleExternalWebClient webClient;

    private CommonService commonService;

    @Autowired
    public RuleService(final CommonService commonService, final RuleExternalRestClient client, final RuleExternalWebClient webClient) {
        this.commonService = commonService;
        this.client = client;
        this.webClient = webClient;
    }

    @Override
    public PaginatedValuesDto<RuleDto> getAllPaginated(final Integer page, final Integer size, final Optional<String> criteria,
            final Optional<String> orderBy, final Optional<DirectionDto> direction, final ExternalHttpContext context) {
        return super.getAllPaginated(page, size, criteria, orderBy, direction, context);
    }

    @Override
    protected Integer beforePaginate(final Integer page, final Integer size) {
        return commonService.checkPagination(page, size);
    }

    @Override public BasePaginatingAndSortingRestClient<RuleDto, ExternalHttpContext> getClient() {
        return client;
    }

    public Collection<RuleDto> getAll(final ExternalHttpContext context, final Optional<String> criteria) {
        return client.getAll(context, criteria);
    }

    public boolean check(ExternalHttpContext context, RuleDto ruleDto) {
        return client.check(context,ruleDto);
    }

    public boolean createRule(ExternalHttpContext context, RuleDto ruleDto) {
    	return client.createRule(context, ruleDto);
    }

    public boolean patchRule(ExternalHttpContext context, Map<String, Object> partialDto, String id) {
    	return client.patchRule(context, partialDto, id);
    }

    public boolean deleteRule(ExternalHttpContext context, String id) {
    	return client.deleteRule(context, id);
    }

    public ResponseEntity<Resource> export(ExternalHttpContext context) {
        return client.export(context);
    }

    public JsonNode importRules(ExternalHttpContext context, MultipartFile file) {
        return webClient.importRules(context, file);
    }
}
