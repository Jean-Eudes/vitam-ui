/*
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2015-2019)
 *
 * contact.vitam@culture.gouv.fr
 *
 * This software is a computer program whose purpose is to implement a digital archiving back-office system managing
 * high volumetry securely and efficiently.
 *
 * This software is governed by the CeCILL 2.1 license under French law and abiding by the rules of distribution of free
 * software. You can use, modify and/ or redistribute the software under the terms of the CeCILL 2.1 license as
 * circulated by CEA, CNRS and INRIA at the following URL "http://www.cecill.info".
 *
 * As a counterpart to the access to the source code and rights to copy, modify and redistribute granted by the license,
 * users are provided only with a limited warranty and the software's author, the holder of the economic rights, and the
 * successive licensors have only limited liability.
 *
 * In this respect, the user's attention is drawn to the risks associated with loading, using, modifying and/or
 * developing or reproducing the software by the user in light of its specific status of free software, that may mean
 * that it is complicated to manipulate, and that also therefore means that it is reserved for developers and
 * experienced professionals having in-depth computer knowledge. Users are therefore encouraged to load and test the
 * software's suitability as regards their requirements in conditions enabling the security of their systems and/or data
 * to be ensured and, more generally, to use and operate it in the same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had knowledge of the CeCILL 2.1 license and that you
 * accept its terms.
 */
package fr.gouv.vitamui.common.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.json.JsonSanitizer;
import fr.gouv.vitam.common.StringUtils;
import fr.gouv.vitam.common.exception.InvalidParseOperationException;
import fr.gouv.vitam.common.json.JsonHandler;
import fr.gouv.vitam.common.logging.SysErrLogger;
import fr.gouv.vitamui.commons.api.exception.InvalidSanitizeCriteriaException;
import fr.gouv.vitamui.commons.api.exception.PreconditionFailedException;
import fr.gouv.vitamui.commons.utils.JsonUtils;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.DefaultValidator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;

/**
 * Checker for Sanity of XML and Json <br>
 * <br>
 * Json : check if json is not exceed the limit size, if json does not contain script tag <br>
 * XML: check if XML file is not exceed the limit size, and it does not contain CDATA, ENTITY or SCRIPT tag
 */
public class SanityChecker {

    private static final String INVALID_IDENTIFIER_SANITIZE = "Sanitizing failed; Invalid input identifier : ";
    private static final String INVALID_HEADER_SANITIZE = "Sanitizing failed; Invalid request header : ";
    private static final String INVALID_CRITERIA = "Criteria failed when sanitizing, it may contains insecure data : ";
    private static final String JSON_IS_NOT_VALID_FROM_SANITIZE_CHECK = "Json is not valid from Sanitize check";
    private static final int DEFAULT_LIMIT_PARAMETER_SIZE = 5000;
    private static final int DEFAULT_LIMIT_FIELD_SIZE = 10000000;
    private static final int DEFAULT_LIMIT_JSON_SIZE = 16000000;
    private static final long DEFAULT_LIMIT_FILE_SIZE = 8000000000L;

    public static final String HTTP_PARAMETER_VALUE = "HTTPParameterValue";
    private static final String HTTP_PARAMETER_NAME = "HTTPParameterName";
    private static final String HTTP_HEADER_NAME = "HTTPHeaderName";
    private static final String HTTP_HEADER_VALUE = "HTTPHeaderValue";

    // TODO : verify the difference between this defined limit and the previous ones
    private static final int REQUEST_LIMIT = 10000;

    /**
     * max size of xml file
     */
    private static long limitFileSize = DEFAULT_LIMIT_FILE_SIZE;
    /**
     * max size of json
     */
    private static long limitJsonSize = DEFAULT_LIMIT_JSON_SIZE;
    /**
     * max size of Json or Xml value field
     */
    private static int limitFieldSize = DEFAULT_LIMIT_FIELD_SIZE;
    /**
     * max size of parameter value field (low)
     */
    private static int limitParamSize = DEFAULT_LIMIT_PARAMETER_SIZE;

    // ISSUE with integration
    private static final Validator ESAPI = init();

    private SanityChecker() {
        // Empty constructor
    }

    private static final Validator init() {
        // ISSUE with integration
        return new DefaultValidator();
    }


    public static boolean isValidFileName(String value) {
        return !isStringInfected(value, HTTP_PARAMETER_VALUE);
    }

    public static boolean isValidParamater(String value) {
        return !isStringInfected(value, HTTP_PARAMETER_VALUE);
    }

    /**
     * Sanitize the json
     *
     * @param json
     * @return sanitized json as String
     * @throws InvalidParseOperationException
     */
    public static String sanitizeJsonNode(JsonNode json) throws InvalidParseOperationException {
        if (json == null) {
            return "";
        }
        final String jsonish = JsonHandler.writeAsString(json);
        try {
            return JsonSanitizer.sanitize(jsonish);
        } catch (final RuntimeException e) {
            throw new InvalidParseOperationException(JSON_IS_NOT_VALID_FROM_SANITIZE_CHECK, e);
        }
    }


    /**
     * checkJsonAll : Check sanity of json : size, invalid tag
     *
     * @param json as JsonNode
     * @throws InvalidParseOperationException when Sanity Check is in error
     */
    public static void checkJsonAll(JsonNode json) throws InvalidParseOperationException, PreconditionFailedException {
        if (json == null || json.isMissingNode()) {
            throw new InvalidParseOperationException(JSON_IS_NOT_VALID_FROM_SANITIZE_CHECK);
        }
        final String jsonish = JsonHandler.writeAsString(json);
        try {
            final String wellFormedJson = JsonSanitizer.sanitize(jsonish);
            if (!wellFormedJson.equals(jsonish)) {
                throw new InvalidParseOperationException(JSON_IS_NOT_VALID_FROM_SANITIZE_CHECK);
            }
        } catch (final RuntimeException e) {
            throw new InvalidParseOperationException(JSON_IS_NOT_VALID_FROM_SANITIZE_CHECK, e);
        }
        checkJsonFileSize(jsonish);
        checkJsonSanity(json);
    }

    /**
     * checkJsonAll : Check sanity of json : size, invalid tag
     *
     * @param json as String
     * @throws InvalidParseOperationException when Sanity Check is in error
     */
    public static void checkJsonAll(String json) throws InvalidParseOperationException, PreconditionFailedException {
        try {
            final String wellFormedJson = JsonSanitizer.sanitize(json);
            if (!wellFormedJson.equals(json)) {
                throw new InvalidParseOperationException(JSON_IS_NOT_VALID_FROM_SANITIZE_CHECK);
            }
        } catch (final RuntimeException e) {
            throw new InvalidParseOperationException(JSON_IS_NOT_VALID_FROM_SANITIZE_CHECK, e);
        }
        checkJsonFileSize(json);
        checkJsonSanity(JsonHandler.getFromString(json));
    }

    /**
     * checkSecureParameter : Check sanity of String: no javascript/xml tag, neither html tag
     * check if the string is not infected or contains illegal characters
     *
     * @param params
     * @throws PreconditionFailedException
     * @throws InvalidParseOperationException
     */
    public static void checkSecureParameter(String... params)
        throws PreconditionFailedException, InvalidParseOperationException {
        for (final String param : params) {
            if(param != null) {
                checkSecureParam(param);
            }
        }
    }

    /**
     * sanitizeCriteria : Check sanity of  an optional String: no javascript/xml tag, neither html tag
     *
     * @param criterias
     * @throws PreconditionFailedException
     * @throws InvalidSanitizeCriteriaException
     */
    public static  void sanitizeCriteria(final Optional<String> ...criterias) {
        for(final Optional<String> criteria : criterias) {
            criteria.ifPresent(c -> {
                try {
                    SanityChecker.checkJsonAll(c);
                } catch (InvalidParseOperationException e) {
                    throw new InvalidSanitizeCriteriaException(INVALID_CRITERIA ,e.getMessage());
                } catch (PreconditionFailedException exception) {
                    throw new PreconditionFailedException("The object is not valid " , exception);
                }

            });
        }

    }

    public static void sanitizeCriteria(Object ...objects) throws PreconditionFailedException, InvalidParseOperationException {
        for(final Object query : objects) {
            JsonNode jsonNode = JsonUtils.toJsonNode(query);
            try {
                SanityChecker.checkJsonAll(jsonNode);
            }  catch (PreconditionFailedException exception) {
                throw new PreconditionFailedException("The object is not valid " , exception);
            }
            catch (InvalidParseOperationException exception) {
                throw new InvalidSanitizeCriteriaException(INVALID_CRITERIA, exception.getMessage());
            }
        }
    }

    /**
     * Find out XSS by ESAPI validator
     *
     * @param value     of string
     * @param validator name declared in ESAPI.properties
     * @return boolean
     */
    private static boolean isStringInfected(String value, String validator) {
        return !ESAPI.isValidInput(validator, value, validator, REQUEST_LIMIT, true);
    }

    public static boolean isIssueOnParameter(String param) {
        try {
            checkSecureParam(param);
            return false;
        } catch (final InvalidParseOperationException | PreconditionFailedException e) {
            SysErrLogger.FAKE_LOGGER.ignoreLog(e);
            return true;
        }
    }

    private static void checkSecureParam(String param)
        throws PreconditionFailedException, InvalidParseOperationException {
        if(isValidParamater(param)) {
            try {
                checkSanityTags(param, getLimitParamSize());
                checkHtmlPattern(param);
            } catch (InvalidParseOperationException exception) {
                throw new InvalidParseOperationException("Error with the parameter ", exception);
            }
        } else {
            throw new PreconditionFailedException("the parameter is not valid");
        }
    }

    /**
     * CheckXMLSanityFileSize : check size of xml file
     *
     * @param xmlFile as File
     * @throws IOException                    when read file exception
     * @throws InvalidParseOperationException when Sanity Check is in error
     */
    protected static void checkXmlSanityFileSize(File xmlFile) throws InvalidParseOperationException {
        if (xmlFile.length() > getLimitFileSize()) {
            throw new InvalidParseOperationException("File size exceeds sanity check");
        }
    }

    /**
     * CheckXMLSanityTags : check invalid tag contains of a xml file
     *
     * @param xmlFile : XML file path as String
     * @throws IOException                    when read file error
     * @throws InvalidParseOperationException when Sanity Check is in error
     */
    protected static void checkXmlSanityTags(File xmlFile) throws InvalidParseOperationException, IOException {
        try (final Reader fileReader = new FileReader(xmlFile)) {
            try (final BufferedReader bufReader = new BufferedReader(fileReader)) {
                String line = null;
                while ((line = bufReader.readLine()) != null) {
                    checkXmlSanityTags(line);
                }
            }
        }
    }

    /**
     * Check for all RULES
     *
     * @param line line to check
     * @throws InvalidParseOperationException when Sanity Check is in error
     */
    private static void checkXmlSanityTags(String line) throws InvalidParseOperationException {
        for (final String rule : StringUtils.RULES) {
            checkSanityTags(line, rule);
        }
    }

    /**
     * Check for all RULES and Esapi
     *
     * @param line  line to check
     * @param limit limit size
     * @throws InvalidParseOperationException when Sanity Check is in error
     */
    private static void checkSanityTags(String line, int limit) throws InvalidParseOperationException {
        checkSanityEsapi(line, limit);
        checkXmlSanityTags(line);
    }

    /**
     * Check using ESAPI from OWASP
     *
     * @param line  line to check
     * @param limit limit size
     * @throws InvalidParseOperationException when Sanity Check is in error
     */
    private static void checkSanityEsapi(String line, int limit) throws InvalidParseOperationException {
        if (line.length() > limit) {
            throw new InvalidParseOperationException("Invalid input bytes length");
        }
        if (StringUtils.UNPRINTABLE_PATTERN.matcher(line).find()) {
            throw new InvalidParseOperationException("Invalid input bytes");
        }
        // ESAPI.getValidPrintable Not OK
        // Issue with integration of ESAPI
        try {
            ESAPI.getValidSafeHTML("CheckSafeHtml", line, limit, true);
        } catch (NoClassDefFoundError | ValidationException | IntrusionException e) {
            throw new InvalidParseOperationException("Invalid ESAPI sanity check", e);
        }
    }

    /**
     * checkSanityTags : check if there is an invalid tag
     *
     * @param invalidTag data to check as String
     * @throws InvalidParseOperationException when Sanity Check is in error
     */
    private static void checkSanityTags(String dataLine, String invalidTag)
        throws InvalidParseOperationException {
        if (dataLine != null && invalidTag != null && dataLine.contains(invalidTag)) {
            throw new InvalidParseOperationException("Invalid tag sanity check");
        }
    }

    /**
     * checkHtmlPattern : check against Html Pattern within value (not allowed)
     *
     * @param param
     * @throws InvalidParseOperationException when Sanity Check is in error
     */
    private static void checkHtmlPattern(String param) throws InvalidParseOperationException {
        if (StringUtils.HTML_PATTERN.matcher(param).find()) {
            throw new InvalidParseOperationException("HTML PATTERN found");
        }
    }

    public static void sanitizeJson(JsonNode json) {
        try {
            SanityChecker.checkJsonSanity(json);
        } catch (InvalidParseOperationException e) {
            throw new InvalidSanitizeCriteriaException(INVALID_CRITERIA, json.toString());
        } catch (PreconditionFailedException exception) {
            throw new PreconditionFailedException("The Json field is not valid", exception);
        }
    }

    /**
     * checkJsonSanity : check sanity of json and find invalid key
     *
     * @param json as JsonNode
     * @throws InvalidParseOperationException when Sanity Check is in error
     */
    public static void checkJsonSanity(JsonNode json) throws InvalidParseOperationException {
        if (json.isArray()) {
            ArrayNode nodes = (ArrayNode) json;
            for (JsonNode element : nodes) {
                checkJsonSanity(element);
            }
        } else {
            final Iterator<Map.Entry<String, JsonNode>> fields = json.fields();
            while (fields.hasNext()) {
                final Map.Entry<String, JsonNode> entry = fields.next();
                final String key = entry.getKey();
                if(isValidParamater(key)) {
                    checkSanityTags(key, getLimitFieldSize());
                } else {
                    throw new PreconditionFailedException("The json key is not valid");
                }
                final JsonNode value = entry.getValue();

                if (value.isArray()) {
                    ArrayNode nodes = (ArrayNode) value;
                    for (JsonNode jsonNode : nodes) {
                        if (!jsonNode.isValueNode()) {
                            checkJsonSanity(jsonNode);
                        } else {
                            validateJSONField(value);
                        }
                    }
                } else if (!value.isValueNode()) {
                    checkJsonSanity(value);
                } else {
                    validateJSONField(value);
                }
            }
        }
    }

    private static void validateJSONField(JsonNode jsonNode) throws InvalidParseOperationException {
        final String jsonAsString = JsonHandler.writeAsString(jsonNode);
        checkSanityTags(jsonAsString, getLimitFieldSize());
        checkHtmlPattern(jsonAsString);
    }

    /**
     * checkJsonFileSize
     *
     * @param json as JsonNode
     * @throws InvalidParseOperationException when Sanity Check is in error
     */
    private static void checkJsonFileSize(String json) throws InvalidParseOperationException {
        if (json.length() > getLimitJsonSize()) {
            throw new InvalidParseOperationException(
                "Json size exceeds sanity check : " + getLimitJsonSize());
        }
    }

    /*
     * @return the limit File Size (XML or JSON)
     */
    public static long getLimitFileSize() {
        return limitFileSize;
    }

    /**
     * @param limitFileSize the limit File Size to set (XML or JSON)
     */
    public static void setLimitFileSize(long limitFileSize) {
        SanityChecker.limitFileSize = limitFileSize;
    }

    /**
     * @return the limit Size of a Json
     */
    public static long getLimitJsonSize() {
        return limitJsonSize;
    }

    /**
     * @param limitJsonSize the limit Size of a Json to set
     */
    public static void setLimitJsonSize(long limitJsonSize) {
        SanityChecker.limitJsonSize = limitJsonSize;
    }

    /**
     * @return the limit Size of a Field in a Json
     */
    public static int getLimitFieldSize() {
        return limitFieldSize;
    }

    /**
     * @param limitFieldSize the limit Size of a Field in a Json to set
     */
    public static void setLimitFieldSize(int limitFieldSize) {
        SanityChecker.limitFieldSize = limitFieldSize;
    }

    /**
     * @return the limit Size of a parameter
     */
    public static int getLimitParamSize() {
        return limitParamSize;
    }

    /**
     * @param limitParamSize the limit Size of a parameter to set
     */
    public static void setLimitParamSize(int limitParamSize) {
        SanityChecker.limitParamSize = limitParamSize;
    }
}
