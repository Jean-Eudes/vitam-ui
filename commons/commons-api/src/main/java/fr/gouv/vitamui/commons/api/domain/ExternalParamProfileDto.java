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
package fr.gouv.vitamui.commons.api.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.NotNull;
import java.time.OffsetDateTime;

@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
@AllArgsConstructor
@NoArgsConstructor
public class ExternalParamProfileDto extends IdDto {

    public static final String PARAM_ACCESS_CONTRACT_NAME = "PARAM_ACCESS_CONTRACT";
    public static final String PARAM_BULK_OPERATIONS_THRESHOLD_NAME = "PARAM_BULK_OPERATIONS_THRESHOLD";

    @NotNull
    @Length(min = 2, max = 100)
    private String name;

    @NotNull
    @Length(min = 2, max = 100)
    private String description;

    @NotNull
    @Length(min = 2, max = 100)
    private String accessContract;

    @Length(min = 2, max = 100)
    private String profileIdentifier;

    @Length(min = 2, max = 100)
    private String idProfile;

    @Length(min = 2, max = 100)
    private String externalParamIdentifier;

    @Length(min = 2, max = 100)
    private String idExternalParam;

    private boolean enabled;

    private boolean usePlatformBulkOperationsThreshold;

    private Integer bulkOperationsThreshold;

    private ParameterDto[] parameters;

    private OffsetDateTime dateTime = OffsetDateTime.now();

    public void transformFields() {
        if (parameters != null && parameters.length > 0) {
            for (ParameterDto parameterDto : parameters) {
                if (parameterDto.getKey().equals(PARAM_BULK_OPERATIONS_THRESHOLD_NAME)) {
                    try {
                        this.bulkOperationsThreshold = Integer.valueOf(parameterDto.getValue());
                    } catch (NumberFormatException nfe) {
                        throw new IllegalArgumentException(
                            "The field bulkOperationsThreshold parameter contains wrong number value");
                    }
                } else if (parameterDto.getKey().equals(PARAM_ACCESS_CONTRACT_NAME)) {
                    this.accessContract = parameterDto.getValue();
                }
            }
        }
    }
}
