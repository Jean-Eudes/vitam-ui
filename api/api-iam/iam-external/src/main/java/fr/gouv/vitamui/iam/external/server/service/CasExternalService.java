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
package fr.gouv.vitamui.iam.external.server.service;

import java.util.List;
import java.util.Optional;

import fr.gouv.vitamui.iam.common.dto.cas.LoginRequestDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import fr.gouv.vitamui.commons.api.domain.UserDto;
import fr.gouv.vitamui.iam.common.dto.SubrogationDto;
import fr.gouv.vitamui.iam.internal.client.CasInternalRestClient;
import fr.gouv.vitamui.iam.security.client.AbstractInternalClientService;
import fr.gouv.vitamui.iam.security.service.ExternalSecurityService;
import lombok.Getter;
import lombok.Setter;

/**
 * Specific CAS service.
 *
 *
 */
@Getter
@Setter
@Service
public class CasExternalService extends AbstractInternalClientService {

    private final CasInternalRestClient casInternalRestClient;

    private final ExternalSecurityService securityService;

    @Autowired
    public CasExternalService(final CasInternalRestClient casInternalRestClient,
            final ExternalSecurityService securityService) {
        super(securityService);
        this.casInternalRestClient = casInternalRestClient;
        this.securityService = securityService;
    }

    public void changePassword(final String username, final String password) {
        getClient().changePassword(getInternalHttpContext(), username, password);
    }

    public UserDto login(final LoginRequestDto dto) {
        return getClient().login(getInternalHttpContext(), dto);
    }

    public UserDto getUserByEmail(final String email, final Optional<String> embedded) {
        return getClient().getUserByEmail(getInternalHttpContext(), email, embedded);
    }

    public UserDto getUser(final String email, final String idp, final Optional<String> userIdentifier, final Optional<String> embedded) {
        return getClient().getUser(getInternalHttpContext(), email, idp, userIdentifier, embedded);
    }

    public UserDto getUserById(final String id) {
        return getClient().getUserById(getInternalHttpContext(), id);
    }

    public List<SubrogationDto> getSubrogationsBySuperUser(final String superUserEmail) {
        return getClient().getSubrogationsBySuperUserEmail(getInternalHttpContext(), superUserEmail);
    }

    public List<SubrogationDto> getSubrogationsBySuperUserId(final String superUserId) {
        return getClient().getSubrogationsBySuperUserId(getInternalHttpContext(), superUserId);
    }

    public void logout(final String authToken, final String superUser) {
        getClient().logout(getInternalHttpContext(), authToken, superUser);
    }

    @Override
    protected CasInternalRestClient getClient() {
        return casInternalRestClient;
    }
}
