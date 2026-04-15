pipeline {
    agent any

    environment {
        // JFrog URL — ubah sesuai instance BCA
        JFROG_URL = 'https://trial789.jfrog.io'

        // Credentials ID dari Jenkins Manage Credentials
        // Tipe: Username with Password, ID: 'jfrog-xray-credentials'
        // Username = JFrog email, Password = JFrog password
        JFROG_CREDS = credentials('jfrog-xray-credentials')

        // Nama virtualenv yang akan dibuat di workspace
        VENV_DIR = '.venv-xray'
    }

    options {
        timestamps()
        // ansiColor('xterm')
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    stages {

        // ================================================================
        // STAGE 1: Checkout
        // ================================================================
        stage('Checkout') {
            steps {
                echo '================================================='
                echo ' Checking out repository...'
                echo '================================================='
                checkout scm
            }
        }

        // ================================================================
        // STAGE 2: Setup Python Environment
        // ================================================================
        stage('Setup Python') {
            steps {
                echo '================================================='
                echo ' Setting up Python virtual environment...'
                echo '================================================='
                script {
                    if (isUnix()) {
                        sh """
                            python3 -m venv ${VENV_DIR}
                            ${VENV_DIR}/bin/pip install --upgrade pip --quiet
                            ${VENV_DIR}/bin/pip install requests --quiet
                            echo "Python version: \$(${VENV_DIR}/bin/python --version)"
                            echo "requests installed: \$(${VENV_DIR}/bin/pip show requests | grep Version)"
                        """
                    } else {
                        bat """
                            python -m venv ${VENV_DIR}
                            ${VENV_DIR}\\Scripts\\pip install --upgrade pip --quiet
                            ${VENV_DIR}\\Scripts\\pip install requests --quiet
                            echo Python ready
                        """
                    }
                }
            }
        }

        // ================================================================
        // STAGE 3: Setup JFrog (Repos + Policy + Watch)
        // ================================================================
        stage('JFrog Setup') {
            steps {
                echo '================================================='
                echo ' Running setup_jfrog_xray.py...'
                echo ' Creating: repos, security policy, Xray watch'
                echo '================================================='
                script {
                    // Credentials dipass sebagai environment variable — AMAN, tidak muncul di log
                    withCredentials([usernamePassword(
                        credentialsId: 'jfrog-xray-credentials',
                        usernameVariable: 'JFROG_USER',
                        passwordVariable: 'JFROG_PASS'
                    )]) {
                        if (isUnix()) {
                            sh """
                                export JFROG_URL=${JFROG_URL}
                                export JFROG_USER=${JFROG_USER}
                                export JFROG_PASS=${JFROG_PASS}
                                ${VENV_DIR}/bin/python scenario-xray-block/setup_jfrog_xray.py
                            """
                        } else {
                            bat """
                                set JFROG_URL=${JFROG_URL}
                                set JFROG_USER=%JFROG_USER%
                                set JFROG_PASS=%JFROG_PASS%
                                ${VENV_DIR}\\Scripts\\python scenario-xray-block\\setup_jfrog_xray.py
                            """
                        }
                    }
                }
            }
        }

        // ================================================================
        // STAGE 4: Wait for Xray Indexing
        // ================================================================
        stage('Wait for Xray Scan') {
            steps {
                echo '================================================='
                echo ' Waiting 60 seconds for Xray to index & scan...'
                echo ' (Xray perlu waktu untuk scan artifact di cache)'
                echo '================================================='
                script {
                    if (isUnix()) {
                        sh 'sleep 60'
                    } else {
                        bat 'ping -n 61 127.0.0.1 > nul'
                    }
                }
            }
        }

        // ================================================================
        // STAGE 5: Run Xray Block Tests (9 Test Cases)
        // ================================================================
        stage('Run Xray Tests') {
            steps {
                echo '================================================='
                echo ' Running test_xray_block.py (9 test cases)...'
                echo ' Expected: BLOCK log4j, jackson, commons-collections'
                echo '           ALLOW gson, slf4j'
                echo '================================================='
                script {
                    withCredentials([usernamePassword(
                        credentialsId: 'jfrog-xray-credentials',
                        usernameVariable: 'JFROG_USER',
                        passwordVariable: 'JFROG_PASS'
                    )]) {
                        if (isUnix()) {
                            sh """
                                export JFROG_URL=${JFROG_URL}
                                export JFROG_USER=${JFROG_USER}
                                export JFROG_PASS=${JFROG_PASS}
                                ${VENV_DIR}/bin/python scenario-xray-block/test_xray_block.py 2>&1 | tee test_output.txt
                                grep -q "9/9 PASSED" test_output.txt
                            """
                        } else {
                            bat """
                                set JFROG_URL=${JFROG_URL}
                                set JFROG_USER=%JFROG_USER%
                                set JFROG_PASS=%JFROG_PASS%
                                ${VENV_DIR}\\Scripts\\python scenario-xray-block\\test_xray_block.py > test_output.txt 2>&1
                                type test_output.txt
                                findstr /C:"9/9 PASSED" test_output.txt
                            """
                        }
                    }
                }
            }
        }
    }

    // ================================================================
    // POST: Notify hasil pipeline
    // ================================================================
    post {
        success {
            echo ''
            echo '================================================='
            echo ' ALL TESTS PASSED!'
            echo ' JFrog Xray block scenario validated successfully.'
            echo ' -> log4j, jackson, commons-collections: BLOCKED'
            echo ' -> gson, slf4j: ALLOWED'
            echo '================================================='
            archiveArtifacts artifacts: 'test_output.txt', allowEmptyArchive: true
        }
        failure {
            echo ''
            echo '================================================='
            echo ' PIPELINE FAILED!'
            echo ' Check test_output.txt for details.'
            echo '================================================='
            archiveArtifacts artifacts: 'test_output.txt', allowEmptyArchive: true
        }
        always {
            echo "Build result: ${currentBuild.currentResult}"
            echo "JFrog URL: ${JFROG_URL}"
            echo "Triggered by: ${env.BUILD_USER ?: 'automated'}"
        }
        cleanup {
            script {
                // Bersihkan virtualenv setelah selesai
                if (isUnix()) {
                    sh "rm -rf ${VENV_DIR} || true"
                } else {
                    bat "rmdir /s /q ${VENV_DIR} || exit 0"
                }
            }
        }
    }
}
