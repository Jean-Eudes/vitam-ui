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
package fr.gouv.vitamui.commons.vitam.api.config;

import fr.gouv.vitamui.commons.vitam.api.config.converter.RuleConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import fr.gouv.vitamui.commons.vitam.api.administration.AccessContractService;
import fr.gouv.vitamui.commons.vitam.api.administration.AgencyService;
import fr.gouv.vitamui.commons.vitam.api.administration.IngestContractService;
import fr.gouv.vitamui.commons.vitam.api.administration.ProfileService;
import fr.gouv.vitamui.commons.vitam.api.administration.RuleService;
import fr.gouv.vitamui.commons.vitam.api.administration.VitamOperationService;

@Configuration
public class VitamAdministrationConfig extends VitamClientConfig {

    @Bean
    public AccessContractService geAccessContractService() {
        return new AccessContractService(adminExternalClient());
    }

    @Bean
    public AgencyService getAgencyService() {
        return new AgencyService(adminExternalClient());
    }

    @Bean
    public VitamOperationService getVitamOperationService() {
        return new VitamOperationService(adminExternalClient());
    }

    @Bean
    public ProfileService getProfileService() {
        return new ProfileService(adminExternalClient());
    }

    @Bean
    public RuleService getRuleService() {
        return new RuleService(adminExternalClient());
    }

    @Bean
    public IngestContractService geIngestContractService() {
        return new IngestContractService(adminExternalClient());
    }

    @Bean
    public RuleConverter rulesConverter() {
        return new RuleConverter();
    }
}
