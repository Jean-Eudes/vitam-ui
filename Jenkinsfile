pipeline {
    agent {
        label 'contrib'
    }

    environment {
        SLACK_MESSAGE = "${env.JOB_NAME} ${env.BUILD_NUMBER} (<${env.RUN_DISPLAY_URL}|Open>)"
        MVN_BASE = "/usr/local/maven/bin/mvn --settings ${pwd()}/.ci/settings.xml"
        MVN_COMMAND = "${MVN_BASE} --show-version --batch-mode --errors --fail-at-end -DinstallAtEnd=true -DdeployAtEnd=true "
        CI = credentials('app-jenkins')
        SERVICE_CHECKMARX_URL = credentials('service-checkmarx-url')
        SERVICE_SONAR_URL = credentials('service-sonar-url')
        SERVICE_GIT_URL = credentials('service-gitlab-url')
        SERVICE_NEXUS_URL = credentials('service-nexus-url')
        SERVICE_PROXY_HOST = credentials('http-proxy-host')
        SERVICE_PROXY_PORT = credentials('http-proxy-port')
        NOPROXY_HOST = credentials('http_nonProxyHosts')
        SERVICE_REPO_SSHURL = credentials('repository-connection-string')
        SERVICE_REPOSITORY_URL = credentials('service-repository-url')
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
        stage('Build common.') {
            steps {
                parallel(
                    'Common': {
                         sh ''' $MVN_COMMAND install -P vitam,sonar-metrics -f commons/pom.xml   '''
                    }
                )
            }
        }

        stage('Build and tests.') {
            steps {
                parallel(
                    'Back install and Security API': {
                        sh ''' $MVN_COMMAND install -P vitam,sonar-metrics -f api/api-security/pom.xml   '''
                    },
                    'Back install and IAM API': {
                        sh ''' $MVN_COMMAND install -P vitam,sonar-metrics -f api/api-iam/pom.xml   '''
                    },
                    'Back install and Archive search API ': {
                        sh ''' $MVN_COMMAND install -P vitam,sonar-metrics -f api/api-archive-search/pom.xml   '''
                    },
                    'Back install and Referentials API ': {
                        sh ''' $MVN_COMMAND install -P vitam,sonar-metrics -f api/api-referential/pom.xml   '''
                    },
                    'Back install and Ingest API ': {
                        sh ''' $MVN_COMMAND install -P vitam,sonar-metrics -f api/api-ingest/pom.xml   '''
                    }
     /*               ,
                    'Back install and Referentials': {
                        sh ''' $MVN_COMMAND install -P vitam,sonar-metrics -pl !ui,!ui/ui-frontend-common,!ui/ui-frontend,!ui/ui-portal,!ui/ui-identity,!ui/ui-referential '''
                    },
                    'Build and Test Ui Frontend Common': {
                        sh ''' $MVN_COMMAND install -DskipAllFrontendTest -DskipTests=true -Pvitam,sonar-metrics -f ui/ui-frontend-common/pom.xml  '''
                    }
                    */
                )
            }
        }

        /*
        stage('Build and tests.') {
            steps {
                parallel(
                    'Back install and Test': {
                        sh ''' $MVN_COMMAND install -Pvitam -pl !ui,!ui/ui-frontend-common,!ui/ui-frontend,!ui/ui-portal,!ui/ui-identity,!ui/ui-referential '''
                    },
                    'Build and Test Ui Frontend Common': {
                        sh ''' $MVN_COMMAND install -DskipAllFrontendTest -DskipTests=true -Pvitam -f ui/ui-frontend-common/pom.xml  '''
                    }
                )
            }
        }
        stage('Ui Frontend') {
            steps {
                parallel(
                    'Build ui parent': {
                        sh ''' $MVN_COMMAND install -DskipTests=true -DskipAllFrontendTest -Pvitam -f ui/pom.xml -pl !ui-frontend-common,!ui-frontend,!ui-portal,!ui-identity,!ui-referential '''
                    },
                    'Build and Test Ui Frontend': {
                        sh ''' $MVN_COMMAND install -Pvitam -DskipAllFrontendTest -DskipTests=true -f ui/ui-frontend/pom.xml '''
                    }
                )
            }
        }

        */
        stage('Uis ') {
            steps {
                parallel(
                    'Ui identity': {
                        sh ''' $MVN_COMMAND install -Pvitam -f ui/ui-identity/pom.xml '''
                    },
                    'Ui portal': {
                        sh ''' $MVN_COMMAND install -Pvitam -f ui/ui-portal/pom.xml '''
                    },
                    'Ui referential': {
                        sh ''' $MVN_COMMAND install -Pvitam -f ui/ui-referential/pom.xml  '''
                    }
                )
            }
        }

        stage('Build sources') {
            environment {
                PUPPETEER_DOWNLOAD_HOST = "${env.SERVICE_NEXUS_URL}/repository/puppeteer-chrome/"
            }
            when {
                environment(name: 'DO_BUILD', value: 'true')
            }
            steps {
                sh 'npmrc default'
                sh '''
                    $MVN_COMMAND deploy -Pvitam,deb,rpm -DskipTests -DskipAllFrontend=true -DskipAllFrontendTests=true -Dlicense.skip=true -pl '!cots/vitamui-nginx,!cots/vitamui-mongod,!cots/vitamui-logstash,!cots/vitamui-mongo-express' $JAVA_TOOL_OPTIONS
                '''
            }
        }

        stage('Build COTS') {
            environment {
                http_proxy = "http://${env.SERVICE_PROXY_HOST}:${env.SERVICE_PROXY_PORT}"
                https_proxy = "http://${env.SERVICE_PROXY_HOST}:${env.SERVICE_PROXY_PORT}"
            }
            when {
                environment(name: 'DO_BUILD', value: 'true')
            }
            steps {
                sh 'npmrc internet'
                dir('cots/') {
                    sh '''
                        $MVN_COMMAND deploy -Pvitam,deb,rpm -DskipTests -Dlicense.skip=true $JAVA_TOOL_OPTIONS
                    '''
                }
            }
        }

        stage('Get publishing scripts') {
            when {
                environment(name: 'DO_PUBLISH', value: 'true')
                environment(name: 'DO_BUILD', value: 'true')
            }
            steps {
                checkout([$class: 'GitSCM',
                    branches: [[name: 'oshimae']],
                    doGenerateSubmoduleConfigurations: false,
                    extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: 'vitam-build.git']],
                    submoduleCfg: [],
                    userRemoteConfigs: [[credentialsId: 'app-jenkins', url: "$SERVICE_GIT_URL"]]
                ])
            }
        }

        stage('Publish rpm and deb') {
            when {
                environment(name: 'DO_PUBLISH', value: 'true')
                environment(name: 'DO_BUILD', value: 'true')
            }
            steps {
                sshagent (credentials: ['jenkins_sftp_to_repository']) {
                    sh 'vitam-build.git/push_vitamui_repo.sh contrib $SERVICE_REPO_SSHURL rpm'
                    sh 'vitam-build.git/push_vitamui_repo.sh contrib $SERVICE_REPO_SSHURL deb'
                }
            }
        }

        stage('Update symlink') {
            when {
                anyOf {
                    branch 'develop*'
                    branch 'master_*'
                    tag pattern: "^[1-9]+(\\.rc)?(\\.[0-9]+)?\\.[0-9]+(-.*)?", comparator: 'REGEXP'
                }
                environment(name: 'DO_PUBLISH', value: 'true')
                environment(name: 'DO_BUILD', value: 'true')
            }
            steps {
                sshagent (credentials: ['jenkins_sftp_to_repository']) {
                    sh 'vitam-build.git/push_symlink_repo.sh contrib $SERVICE_REPO_SSHURL'
                }
            }
        }

        stage('Checkmarx analysis') {
            when {
                anyOf {
                    branch 'develop*'
                    branch 'master_*'
                    branch 'master'
                    tag pattern: "^[1-9]+(\\.rc)?(\\.[0-9]+)?\\.[0-9]+(-.*)?", comparator: 'REGEXP'
                }
                environment(name: 'DO_CHECKMARX', value: 'true')
            }
            environment {
                JAVA_TOOL_OPTIONS = ''
            }
            steps {
                dir('vitam-build.git') {
                    deleteDir()
                }
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
