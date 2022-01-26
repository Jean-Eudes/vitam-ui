/*
Copyright © CINES - Centre Informatique National pour l'Enseignement Supérieur (2021)

[dad@cines.fr]

This software is a computer program whose purpose is to provide
a web application to create, edit, import and export archive
profiles based on the french SEDA standard
(https://redirect.francearchives.fr/seda/).


This software is governed by the CeCILL-C  license under French law and
abiding by the rules of distribution of free software.  You can  use,
modify and/ or redistribute the software under the terms of the CeCILL-C
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info".

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability.

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or
data to be ensured and,  more generally, to use and operate it in the
same conditions as regards security.

The fact that you are presently reading this means that you have had
knowledge of the CeCILL-C license and that you accept its terms.
*/

package fr.gouv.vitamui.pastis.common.service;

import fr.gouv.vitamui.pastis.common.dto.ElementProperties;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

@Service
public class PuaFromJSON {

    private static final Logger LOGGER = LoggerFactory.getLogger(JsonFromPUA.class);
    private static final String schema = "http://json-schema.org/draft-04/schema";
    private static final String type = "object";
    private static final Boolean additionalProperties = false;
    @Autowired
    private PuaPastisValidator puaPastisValidator;

    public String getControlSchemaFromElementProperties(ElementProperties elementProperties) throws IOException {
        // We use a JSONObject instead of POJO, since Jackson and Gson will add unnecessary
        // backslashes during mapping string object values back to string;
        JSONObject controlSchema = puaPastisValidator.sortedJSONObject();
        // 1. Add Schema
        controlSchema.put("$schema", schema);
        // 2. Add  type
        controlSchema.put("type", type);
        // 3. Add additionProperties
        controlSchema.put("additionalProperties", additionalProperties);
        // 4. Check if tree contains Management metadata
        controlSchema = addPatternProperties(elementProperties, controlSchema);
        List<ElementProperties> elementsForTree = puaPastisValidator.ignoreMetadata(elementProperties);

        controlSchema.put("required", puaPastisValidator.getHeadRequired(elementsForTree));

        //controlSchema.put("required",puaPastisValidator.getRequiredProperties(elementProperties));
        // 5. Add definitions;
        JSONObject definitionsFromBasePua = puaPastisValidator.getDefinitionsFromExpectedProfile();
        controlSchema.put("definitions", definitionsFromBasePua);
        // 6. Add ArchiveUnitProfile and the rest of the tree

        JSONArray allElements = puaPastisValidator.getJSONObjectFromAllTree(elementsForTree);
        JSONObject sortedElements = getJSONObjectsFromJSonArray(allElements);
        controlSchema.put("properties", sortedElements);
        // 7. Remove excessive backslashes from mapping strings to objects and vice-versa;
        String cleanedJSON = controlSchema.toString().replaceAll("[\\\\]+", "");
        return cleanedJSON;
    }

    public String getDefinitions() {
        return puaPastisValidator.getDefinitionsFromExpectedProfile().toString();
    }

    private JSONObject getJSONObjectsFromJSonArray(JSONArray array) {
        JSONObject sortedJSONObject = puaPastisValidator.sortedJSONObject();
        Iterator<Object> iterator = array.iterator();
        while (iterator.hasNext()) {
            JSONObject jsonObject = (JSONObject) iterator.next();
            for (String key : jsonObject.keySet()) {
                sortedJSONObject.put(key, jsonObject.get(key));
            }
        }
        return sortedJSONObject;
    }

    private JSONObject addPatternProperties(ElementProperties elementProperties, JSONObject controlSchema)
        throws IOException {
        if (!puaPastisValidator.containsManagement(elementProperties)) {
            controlSchema.put("patternProperties", new JSONObject().put("#management", new JSONObject()));
        }
        return controlSchema;
    }

}