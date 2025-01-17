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
package fr.gouv.vitamui.commons.vitam.api.config.converter;

import fr.gouv.vitam.common.model.administration.FileRulesModel;
import fr.gouv.vitam.common.model.administration.RuleMeasurementEnum;
import fr.gouv.vitam.common.model.administration.RuleType;
import fr.gouv.vitamui.commons.rest.dto.RuleDto;
import fr.gouv.vitamui.commons.utils.VitamUIUtils;

import java.util.List;
import java.util.stream.Collectors;

public class RuleConverter {

    public FileRulesModel convertDtoToVitam(final RuleDto dto) {
        final FileRulesModel rule = VitamUIUtils.copyProperties(dto, new FileRulesModel());
        rule.setRuleType(RuleType.getEnumFromName(dto.getRuleType()));
        rule.setRuleMeasurement(RuleMeasurementEnum.getEnumFromType(dto.getRuleMeasurement()));
        return rule;
    }

    public RuleDto convertVitamToDto(final FileRulesModel rule) {
        final RuleDto dto = VitamUIUtils.copyProperties(rule, new RuleDto());
        dto.setRuleMeasurement(rule.getRuleMeasurement().getType());
        dto.setRuleType(rule.getRuleType().name());
        return dto;
    }

    public List<FileRulesModel> convertDtosToVitams(final List<RuleDto> dtos) {
        return dtos.stream().map(this::convertDtoToVitam).collect(Collectors.toList());
    }

    public List<RuleDto> convertVitamsToDtos(final List<FileRulesModel> rules) {
        return rules.stream().map(this::convertVitamToDto).collect(Collectors.toList());
    }

}
