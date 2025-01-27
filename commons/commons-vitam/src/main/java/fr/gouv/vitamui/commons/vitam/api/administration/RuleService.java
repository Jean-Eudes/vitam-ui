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
package fr.gouv.vitamui.commons.vitam.api.administration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import fr.gouv.vitam.access.external.client.AdminExternalClient;
import fr.gouv.vitam.access.external.common.exception.AccessExternalClientException;
import fr.gouv.vitam.common.client.VitamContext;
import fr.gouv.vitam.common.database.builder.query.QueryHelper;
import fr.gouv.vitam.common.database.builder.request.exception.InvalidCreateOperationException;
import fr.gouv.vitam.common.database.builder.request.single.Select;
import fr.gouv.vitam.common.exception.InvalidParseOperationException;
import fr.gouv.vitam.common.exception.VitamClientException;
import fr.gouv.vitam.common.model.RequestResponse;
import fr.gouv.vitam.common.model.administration.FileRulesModel;
import fr.gouv.vitam.common.model.administration.RuleMeasurementEnum;
import fr.gouv.vitamui.commons.api.exception.UnexpectedDataException;
import fr.gouv.vitamui.commons.vitam.api.dto.RuleNodeResponseDto;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.InputStream;
import java.util.Optional;

public class RuleService {

    private final AdminExternalClient adminExternalClient;

    private ObjectMapper objectMapper;

    @Autowired
    public RuleService(final AdminExternalClient adminExternalClient) {
        this.adminExternalClient = adminExternalClient;
        objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @SuppressWarnings("rawtypes")
    public RequestResponse uploadRules(final VitamContext vitamContext, final InputStream rules, final String filename)
        throws VitamClientException, AccessExternalClientException, InvalidParseOperationException {
        return adminExternalClient.createRules(vitamContext, rules, filename);
    }

    public RequestResponse<FileRulesModel> findRules(final VitamContext vitamContext, final JsonNode select)
        throws VitamClientException {
        return adminExternalClient.findRules(vitamContext, select);
    }

    public Optional<Long> findRulesDurationByRuleId(final VitamContext vitamContext, final String ruleId)
        throws VitamClientException, InvalidCreateOperationException, JsonProcessingException {
        final Select select = new Select();
        select.setQuery(QueryHelper.eq("RuleId", ruleId));
        RequestResponse<FileRulesModel> rulesVitamResponse =
            this.findRules(vitamContext, select.getFinalSelect());
        if (rulesVitamResponse.isOk()) {
            RuleNodeResponseDto ruleNodeResponseDto = objectMapper
                .treeToValue(rulesVitamResponse.toJsonNode(), RuleNodeResponseDto.class);
            FileRulesModel rule = ruleNodeResponseDto.getResults().get(0);
            if (RuleMeasurementEnum.YEAR.equals(rule.getRuleMeasurement())) {
                return Optional.of(Long.parseLong(rule.getRuleDuration()));
            } else {
                throw new UnexpectedDataException("The rule duration measurement should be in years.");
            }
        }
        return Optional.empty();
    }
}
