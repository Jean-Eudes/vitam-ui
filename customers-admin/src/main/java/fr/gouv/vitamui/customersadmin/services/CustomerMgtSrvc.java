/*
 * Copyright French Prime minister Office/SGMAP/DINSIC/Vitam Program (2015-2022)
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

package fr.gouv.vitamui.customersadmin.services;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import fr.gouv.vitamui.commons.api.domain.ServicesData;
import fr.gouv.vitamui.commons.api.logger.VitamUILogger;
import fr.gouv.vitamui.commons.api.logger.VitamUILoggerFactory;
import fr.gouv.vitamui.commons.rest.client.ExternalHttpContext;
import fr.gouv.vitamui.customersadmin.configs.CustomerMgtProperties;
import fr.gouv.vitamui.iam.common.dto.CustomerCreationFormData;
import fr.gouv.vitamui.iam.common.dto.CustomerDto;
import fr.gouv.vitamui.iam.external.client.IamExternalWebClientFactory;
import org.apache.commons.lang3.time.DateUtils;
import org.bson.BsonDocument;
import org.bson.BsonString;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

import static com.mongodb.client.model.Filters.eq;

@Service
public class CustomerMgtSrvc {

    protected static final VitamUILogger LOGGER = VitamUILoggerFactory.getInstance(CustomerMgtSrvc.class);

    public static final String ADMIN_USER = "admin_user";
    public static final String TOKEN_USER_ADMIN = "tokenadmin";
    protected static final String TESTS_CONTEXT_ID = "integration-tests_context";
    private MongoCollection<Document> tokensCollection;
    private MongoDatabase iamDatabase;
    private MongoCollection<Document> usersCollection;
    private MongoDatabase securityDatabase;
    private static MongoClient mongoClientSecurity;

    private MongoCollection<Document> contextsCollection;

    private MongoCollection<Document> certificatesCollection;
    protected static final String TESTS_CERTIFICATE_ID = "integration-tests_cert";

    private MongoCollection<Document> profilesCollection;

    private static MongoClient mongoClientIam;

    protected static final String TESTS_USER_ADMIN = "tokenadmin";

    protected static final String SYSTEM_USER_ID = "admin_user";

    public static final String ADMIN_USER_GROUP = "5c79022e7884583d1ebb6e5d0bc0121822684250a3fd2996fd93c04634363363";

    @Autowired
    private CustomerMgtProperties customerMgtProperties;

    @Autowired
    private IamExternalWebClientFactory iamWebClientFactory;


    protected ExternalHttpContext getSystemTenantUserAdminContext() {
        buildSystemTenantUserAdminContext();
        return new ExternalHttpContext(customerMgtProperties.getProofTenantIdentifier(), TOKEN_USER_ADMIN,
            TESTS_CONTEXT_ID, "admincaller", "requestId", "ContratTNR");
    }

    private void buildSystemTenantUserAdminContext() {
        getUsersCollection().updateOne(new BsonDocument("_id", new BsonString(ADMIN_USER)),
            new BsonDocument("$set", new BsonDocument("groupId", new BsonString(ADMIN_USER_GROUP))));
        tokenUserAdmin();
    }

    public CustomerDto createCustomer(final ExternalHttpContext context,
        final CustomerCreationFormData customerCreationFormData) {
        LOGGER.debug("Create {} ", customerCreationFormData);
        CustomerDto customerDto = iamWebClientFactory.getCustomerWebClient().create(context, customerCreationFormData);

        return customerDto;
    }

    public CustomerDto createCustomer(final ExternalHttpContext context, final CustomerDto customerDto,
        final Optional<Path> logoPath) {
        LOGGER.debug("Create {} with logo : {}", customerDto, logoPath);
        return iamWebClientFactory.getCustomerWebClient().create(context, customerDto, logoPath);

    }



    protected void tokenUserAdmin() {
        writeToken(TESTS_USER_ADMIN, SYSTEM_USER_ID);
    }

    protected void writeToken(final String id, final String userId) {
        getTokensCollection().deleteOne(eq("_id", id));
        final Document token =
            new Document("_id", id).append("updatedDate", DateUtils.addDays(new Date(), -10)).append("refId", userId);
        getTokensCollection().insertOne(token);
    }

    protected MongoCollection<Document> getTokensCollection() {
        if (tokensCollection == null) {
            tokensCollection = getIamDatabase().getCollection("tokens");
        }
        return tokensCollection;
    }

    protected MongoClient getMongoIam() {
        if (mongoClientIam == null) {
            mongoClientIam = MongoClients.create(customerMgtProperties.getMongoIamUri());
        }
        return mongoClientIam;
    }

    protected MongoDatabase getIamDatabase() {
        if (iamDatabase == null) {
            iamDatabase = getMongoIam().getDatabase("iam");
        }
        return iamDatabase;
    }

    protected MongoCollection<Document> getUsersCollection() {
        if (usersCollection == null) {
            usersCollection = getIamDatabase().getCollection("users");
        }
        return usersCollection;
    }

    protected MongoDatabase getSecurityDatabase() {
        if (securityDatabase == null) {
            securityDatabase = getMongoSecurity().getDatabase("security");
        }
        return securityDatabase;
    }

    protected MongoClient getMongoSecurity() {
        if (mongoClientSecurity == null) {
            mongoClientSecurity = MongoClients.create(customerMgtProperties.getMongoSecurityUri());
        }
        return mongoClientSecurity;
    }

    protected MongoCollection<Document> getCertificatesCollection() {
        if (certificatesCollection == null) {
            certificatesCollection = getSecurityDatabase().getCollection("certificates");
        }
        return certificatesCollection;
    }

    protected MongoCollection<Document> getContextsCollection() {
        if (contextsCollection == null) {
            contextsCollection = getSecurityDatabase().getCollection("contexts");
        }
        return contextsCollection;
    }

    protected void prepareGenericContext(final boolean fullAccess, final Integer[] tenants, final String[] roles) {
        // recreate generic context
        getContextsCollection().deleteOne(eq("_id", TESTS_CONTEXT_ID));
        //@formatter:off
        final Document itContext = new Document("_id", TESTS_CONTEXT_ID)
            .append("name", "" + new Date())
            .append("fullAccess", fullAccess)
            .append("roleNames", Arrays.asList(roles));
        //@formatter:on
        if (tenants != null) {
            itContext.append("tenants", Arrays.asList(tenants));
        } else {
            itContext.append("tenants", Arrays.asList(new Integer[] {-1}));
        }
        getContextsCollection().insertOne(itContext);

        // recreate generic certificate
        getCertificatesCollection().deleteOne(eq("_id", TESTS_CERTIFICATE_ID));
        //@formatter:off
        try {
            final String certificate =
                getCertificate("JKS", customerMgtProperties.getGenericCert(),
                    customerMgtProperties.getJksPassword().toCharArray());

            final Document itCertificate = new Document("_id", TESTS_CERTIFICATE_ID)
                .append("contextId", TESTS_CONTEXT_ID)
                .append("subjectDN", "subjectDN")
                .append("issuerDN", "issuerDN")
                .append("serialNumber", "serialNumberAdmin")
                .append("data", certificate);
            getCertificatesCollection().insertOne(itCertificate);

        } catch (final Exception e) {
            LOGGER.error("Retrieving generic certificate failed [cert={}, password:{}, exception :{}]",
                customerMgtProperties.getGenericCert(),
                customerMgtProperties.getJksPassword(), e);
        }
        //@formatter:on
    }

    private String getCertificate(final String type, final String filename, final char[] password)
        throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String result = "";
        final KeyStore keyStore = KeyStore.getInstance(type);
        final File key = new ClassPathResource(filename).getFile();
        try (InputStream in = new FileInputStream(key)) {
            keyStore.load(in, password);
        }
        final Enumeration<?> enumeration = keyStore.aliases();
        while (enumeration.hasMoreElements()) {
            final String alias = (String) enumeration.nextElement();
            final Certificate certificate = keyStore.getCertificate(alias);
            final byte[] encodedCertKey = certificate.getEncoded();
            result = Base64.getEncoder().encodeToString(encodedCertKey);
        }

        return result;
    }

    public void createCustomers() throws IOException {
        //read json file
        List<CustomerCreationFormData> customersListToCreate = readFromCustomersFile();
        if (customersListToCreate != null) {
            prepareGenericContext(true, null, new String[] {ServicesData.ROLE_CREATE_CUSTOMERS});
            for (CustomerCreationFormData customerCreationFormData : customersListToCreate) {
                CustomerDto customerDto = createCustomer(getSystemTenantUserAdminContext(), customerCreationFormData);
                LOGGER.info("Customer with name {} and id {} is created ", customerDto.getName(),
                    customerDto.getIdentifier());
            }
        }
    }

    /**
     * @return
     */
    private List<CustomerCreationFormData> readFromCustomersFile() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        List<CustomerCreationFormData> customerList =
            mapper.readValue(customerMgtProperties.getCustomersFile().getFile(),
                new TypeReference<List<CustomerCreationFormData>>() {
                });
        return customerList;
    }
}