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
package fr.gouv.vitamui.iam.common.dto;

import java.util.List;
import java.util.Map;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import fr.gouv.vitamui.iam.common.enums.AuthnRequestBindingEnum;
import org.hibernate.validator.constraints.Length;

import fr.gouv.vitamui.commons.api.domain.CustomerIdDto;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * The DTO v1 for an identity provider.
 *
 *
 */
@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true, exclude = { "keystoreBase64", "keystorePassword", "privateKeyPassword", "idpMetadata",
        "spMetadata" })
public class IdentityProviderDto extends CustomerIdDto {

    /**
     *
     */
    private static final long serialVersionUID = 2372968720503585884L;

    // Common data to all providers
    private String identifier;

    @NotNull
    @Length(min = 2, max = 100)
    private String name;

    private String technicalName;

    @NotNull
    private Boolean internal;

    @NotNull
    private Boolean enabled;

    @NotNull
    @Size(min = 1)
    private List<String> patterns;

    private boolean readonly;


    // Common data to external providers (SAML + OIDC)
    private String mailAttribute;

    private String identifierAttribute;

    private boolean autoProvisioningEnabled;


    // SAML provider data
    private String keystoreBase64;

    private String keystorePassword;

    private String privateKeyPassword;

    private String idpMetadata;

    private String spMetadata;

    private Integer maximumAuthenticationLifetime;

    private AuthnRequestBindingEnum authnRequestBinding = AuthnRequestBindingEnum.POST;


    // OIDC provider data
    private String clientId;

    private String clientSecret;

    private String discoveryUrl;

    private String scope;

    private String preferredJwsAlgorithm;

    private Map<String, String> customParams;

    private Boolean useState;

    private Boolean useNonce;

    private Boolean usePkce;

    private String protocoleType;
}
