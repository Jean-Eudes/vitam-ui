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
package fr.gouv.vitamui.ui.commons.config;

import fr.gouv.vitamui.commons.rest.client.configuration.RestClientConfiguration;
import fr.gouv.vitamui.ui.commons.property.BaseUrl;
import fr.gouv.vitamui.ui.commons.property.UIProperties;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
public class UIPropertiesImpl implements UIProperties {
    /**
     * Prefix URL RestController
     */
    private String prefix;

    /**
     * Limitation for pagination
     */
    private Integer limitPagination = Integer.MAX_VALUE;

    /**
     * baseUrl for applications
     */
    private BaseUrl baseUrl = new BaseUrl();

    private RestClientConfiguration iamExternalClient;

    private String portalLogo;

    private String headerLogo;

    private String footerLogo;

    private String portalTitle;

    private String portalMessage;

    private Map<String, String> themeColors;

    private String assets;

    private String platformName;

    private Map<String, String> customer;

    private String userLogo;

    /**
     * Map of application categories (key: category ID, value: category properties)
     */
    private Map<String, Map<String,Object>> portalCategories;

    private String versionRelease;

    private RestClientConfiguration referentialExternalClient;
}
