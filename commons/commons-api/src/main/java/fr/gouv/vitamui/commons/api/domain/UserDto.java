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

import java.time.OffsetDateTime;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import fr.gouv.vitamui.commons.api.deserializer.ToLowerCaseConverter;
import org.hibernate.validator.constraints.Length;

import fr.gouv.vitamui.commons.api.enums.UserStatusEnum;
import fr.gouv.vitamui.commons.api.enums.UserTypeEnum;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * A DTO with an identifier.
 *
 *
 */
@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class UserDto extends CustomerIdDto {

    private static final long serialVersionUID = -7977759384732830987L;

    @NotNull
    @Length(min = 2, max = 50)
    private String lastname;

    @NotNull
    @Length(min = 2, max = 50)
    private String firstname;

    // no validations for identifier. Because during the creation step, the identifier is set by the backend.
    private String identifier;

    @NotNull
    private String groupId;

    @NotNull
    @Length(min = 4, max = 100)
    @Email
    @JsonDeserialize(converter = ToLowerCaseConverter.class)
    private String email;

    private boolean otp;

    private boolean subrogeable;

    private String phone;

    private String mobile;

    private OffsetDateTime lastConnection;

    private int nbFailedAttempts = 0;

    @NotNull
    private UserStatusEnum status = UserStatusEnum.ENABLED;

    @NotNull
    private UserTypeEnum type;

    private boolean readonly = false;

    private String level = "";

    private OffsetDateTime passwordExpirationDate;

    private AddressDto address = new AddressDto();

    private String internalCode;

    private AnalyticsDto analytics;

    private String siteCode;

    private OffsetDateTime disablingDate;

    private OffsetDateTime removingDate;

    private String centerCode;

    private boolean autoProvisioningEnabled;

    @NotNull
    private String userInfoId;
}
