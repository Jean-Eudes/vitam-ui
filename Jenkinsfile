pipeline {
    agent {
        label 'contrib'
    }

    environment {
        SLACK_MESSAGE = "${env.JOB_NAME} ${env.BUILD_NUMBER} (<${env.RUN_DISPLAY_URL}|Open>)"
        MVN_BASE = "/usr/local/maven/bin/mvn --settings ${pwd()}/.ci/settings.xml"
        MVN_COMMAND = "${MVN_BASE} --show-version --batch-mode --errors --fail-at-end -DinstallAtEnd=true -DdeployAtEnd=true "
        CI = credentials("app-jenkins")
        SERVICE_CHECKMARX_URL = credentials("service-checkmarx-url")
        SERVICE_SONAR_URL = credentials("service-sonar-url")
        SERVICE_GIT_URL = credentials("service-gitlab-url")
        SERVICE_NEXUS_URL = credentials("service-nexus-url")
        SERVICE_PROXY_HOST = credentials("http-proxy-host")
        SERVICE_PROXY_PORT = credentials("http-proxy-port")
        NOPROXY_HOST = credentials("http_nonProxyHosts")
        SERVICE_REPO_SSHURL = credentials("repository-connection-string")
        SERVICE_REPOSITORY_URL=credentials("service-repository-url")
        JAVA_TOOL_OPTIONS = "-Dhttp.proxyHost=${env.SERVICE_PROXY_HOST} -Dhttp.proxyPort=${env.SERVICE_PROXY_PORT} -Dhttps.proxyHost=${env.SERVICE_PROXY_HOST} -Dhttps.proxyPort=${env.SERVICE_PROXY_PORT} -Dhttp.nonProxyHosts=${env.NOPROXY_HOST}"
    }

    options {
        disableConcurrentBuilds()
        buildDiscarder(
            logRotator(
                artifactDaysToKeepStr: '',
                artifactNumToKeepStr: '',
                numToKeepStr: '100'
            )
        )
    }

//    triggers {
//        cron('45 2 * * *')
//    }

    stages {
        stage('Activate steps') {
            agent none
            steps {
                script {
                    env.DO_MAJ_CONTEXT = 'true'
                    env.DO_TEST = 'true'
                    env.DO_BUILD = 'true'
                    env.DO_PUBLISH = 'true'
                    env.DO_CHECKMARX = 'true'
                }
            }
        }

        stage('Upgrade build context') {
	    when {
                environment(name: 'DO_MAJ_CONTEXT', value: 'true')
            }
            environment {
                NODE_JS_DOWNLOAD_URL="https://rpm.nodesource.com/setup_16.x"
                http_proxy="http://${env.SERVICE_PROXY_HOST}:${env.SERVICE_PROXY_PORT}"
                https_proxy="http://${env.SERVICE_PROXY_HOST}:${env.SERVICE_PROXY_PORT}"
            }
            steps {
                sh 'sudo yum install -y gcc-c++ make'
                sh 'sudo yum remove -y nodejs'
                sh 'curl -sL https://rpm.nodesource.com/setup_16.x | sudo -E bash -'
          //      sh 'sudo yum install -y nodejs'
                sh 'sudo yum install -y nodejs-16.9.0-1nodesource'
                sh 'node -v'
                sh '/usr/bin/node -v'
                sh 'npm -v'
                sh 'sudo rm /usr/local/bin/node || true'
                sh 'sudo rm /usr/local/bin/npm || true'
                sh 'node -v;npm -v'
            }
        }


        stage("Checkmarx analysis") {
            when {
                anyOf {
                    branch "vas_vitamui_checkmarx"
                    branch "develop*"
                    branch "master_*"
                    branch "master"
                    tag pattern: "^[1-9]+(\\.rc)?(\\.[0-9]+)?\\.[0-9]+(-.*)?", comparator: "REGEXP"
                }
                environment(name: 'DO_CHECKMARX', value: 'true')
            }
            environment {
                JAVA_TOOL_OPTIONS = ""
            }
            steps {
                dir('vitam-build.git') {
                    deleteDir()
                }
                sh 'echo "${PWD}"'
                sh 'mkdir -p target'
                sh 'mkdir -p logs'
                // KWA : Visibly, backslash escape hell. \\ => \ in groovy string.
                sh '/opt/CxConsole/runCxConsole.sh scan --verbose -Log "${PWD}/logs/cxconsole.log" -CxServer "$SERVICE_CHECKMARX_URL" -CxUser "VITAM openLDAP\\\\$CI_USR" -CxPassword \\"$CI_PSW\\" -ProjectName "CxServer\\SP\\Vitam\\Users\\vitam-ui $GIT_BRANCH" -LocationType folder -locationPath "${PWD}/"  -Preset "Default 2014" -LocationPathExclude "cots,deployment,deploymentByVitam,docs,integration-tests,tools,node,node_modules,dist,target" -LocationFilesExclude "*.rpm,*.pdf" -ForceScan -ReportPDF "${PWD}/target/checkmarx-report.pdf"'
            }
            post {
                success {
                    archiveArtifacts (
                        artifacts: 'target/checkmarx-report.pdf',
                        fingerprint: true
                    )
                }
                failure {
                    archiveArtifacts (
                        artifacts: 'logs/cxconsole.log',
                        fingerprint: true
                    )
                }
            }
        }
    }
}
