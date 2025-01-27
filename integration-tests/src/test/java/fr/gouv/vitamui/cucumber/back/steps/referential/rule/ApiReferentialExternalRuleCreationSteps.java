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
package fr.gouv.vitamui.cucumber.back.steps.referential.rule;

import com.fasterxml.jackson.databind.JsonNode;
import fr.gouv.vitamui.commons.rest.dto.RuleDto;
import fr.gouv.vitamui.cucumber.common.CommonSteps;
import fr.gouv.vitamui.referential.common.utils.ReferentialDtoBuilder;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.apache.commons.io.IOUtils;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Teste l'API Rules dans Referential admin : operations de creation.
 *
 *
 */

public class ApiReferentialExternalRuleCreationSteps extends CommonSteps {

    private JsonNode response;

    @When("^un utilisateur avec le role ROLE_CREATE_RULES ajoute une nouvelle regle en utilisant un certificat full access avec le role ROLE_CREATE_RULES$")
    public void un_utilisateur_avec_le_role_ROLE_CREATE_RULES_ajoute_une_nouvelle_regle_en_utilisant_un_certificat_full_access_avec_le_role_ROLE_CREATE_RULES() {
        final RuleDto ruleDto = ReferentialDtoBuilder.buildRuleDto(null, "RuleTest", "StorageRule", "Test rule value 1", "Test rule Description 1", "1", "DAY");
        testContext.savedRuleDto = getRuleRestClient().create(getSystemTenantUserAdminContext(), ruleDto);
    }

    @Then("^le serveur retourne la regle creee$")
    public void le_serveur_retourne_la_regle_creee() {
        assertThat(testContext.savedRuleDto).overridingErrorMessage("la reponse retournee est null").isNotNull();
    }

    @When("^un utilisateur importe des règles à partir d'un fichier csv valide$")
    public void un_utilisateur_importe_des_regles_à_partir_d_un_fichier_csv_valide() throws IOException {
	    File file = new File("src/test/resources/data/import_rules_valid.csv");
	    FileInputStream input = new FileInputStream(file);
	    MultipartFile multipartFile = new MockMultipartFile("import_rules_valid.csv",
	    	file.getName(), "application/csv", IOUtils.toByteArray(input));
	    response = getFileFormatWebClient().importFileFormats(getSystemTenantUserAdminContext(), multipartFile);
    }

    @Then("^l'import des règles a réussi$")
    public void l_import_règles_a_réussi() {
        assertThat(response).isNotNull();
        assertThat(response.get("httpCode").asInt()).isEqualTo(200);
    }

    @When("^un utilisateur importe des règles à partir d'un fichier csv invalide$")
    public void un_utilisateur_importe_des_formats_de_fichier_à_partir_d_un_fichier_csv_invalide() throws IOException {
	    File file = new File("src/test/resources/data/import_rules_invalid.csv");
	    FileInputStream input = new FileInputStream(file);
	    MultipartFile multipartFile = new MockMultipartFile("import_rules_invalid.csv",
	    	file.getName(), "application/csv", IOUtils.toByteArray(input));
	    response = getFileFormatWebClient().importFileFormats(getSystemTenantUserAdminContext(), multipartFile);
    }

    @Then("^l'import des règles a échoué$")
    public void l_import_des_règles_a_échoué() {
        assertThat(response).isNotNull();
        assertThat(response.get("httpCode").asInt()).isEqualTo(400);
    }

}
