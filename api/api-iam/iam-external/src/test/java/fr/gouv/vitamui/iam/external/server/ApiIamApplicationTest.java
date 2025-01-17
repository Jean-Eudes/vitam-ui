package fr.gouv.vitamui.iam.external.server;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import fr.gouv.vitamui.iam.external.server.config.ApiIamApplicationProperties;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest
public class ApiIamApplicationTest {

    @Autowired
    private Environment env;

    @Autowired
    private ApiIamApplicationProperties iamProperties;

    @Test
    public void testContextLoads() {
        assertThat(env).isNotNull();

        assertThat(iamProperties).isNotNull();
        assertThat(iamProperties.getIamInternalClient()).isNotNull();
    }

}

