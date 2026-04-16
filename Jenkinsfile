pipeline {
    agent any

    environment {
        // JFrog URL — ubah sesuai instance BCA
        JFROG_URL = 'https://trial789.jfrog.io'

        // Credentials ID dari Jenkins Manage Credentials
        // Tipe: Username with Password, ID: 'jfrog-rahman-credential'
        // Username = JFrog email, Password = JFrog password
        JFROG_CREDS = credentials('jfrog-rahman-credential')

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
                        credentialsId: 'jfrog-rahman-credential',
                        usernameVariable: 'JFROG_USER',
                        passwordVariable: 'JFROG_PASS'
                    )]) {
                        if (isUnix()) {
                            sh """
                                export JFROG_URL=${JFROG_URL}
                                export JFROG_USER=${JFROG_USER}
                                export JFROG_PASS=${JFROG_PASS}
                                ${VENV_DIR}/bin/python setup_jfrog_xray.py
                            """
                        } else {
                            bat """
                                set JFROG_URL=${JFROG_URL}
                                set JFROG_USER=%JFROG_USER%
                                set JFROG_PASS=%JFROG_PASS%
                                ${VENV_DIR}\\Scripts\\python setup_jfrog_xray.py
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
                echo ' Waiting 30 seconds initial buffer for Xray...'
                echo ' (Main polling happens in test script - up to 5 min)'
                echo ' '
                echo '================================================='
                script {
                    if (isUnix()) {
                        sh 'sleep 30'
                    } else {
                        bat 'ping -n 31 127.0.0.1 > nul'
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
                        credentialsId: 'jfrog-rahman-credential',
                        usernameVariable: 'JFROG_USER',
                        passwordVariable: 'JFROG_PASS'
                    )]) {
                        if (isUnix()) {
                            sh """
                                export JFROG_URL=${JFROG_URL}
                                export JFROG_USER=${JFROG_USER}
                                export JFROG_PASS=${JFROG_PASS}
                                export XRAY_WAIT_SECS=10
                                export XRAY_MAX_WAIT=300
                                ${VENV_DIR}/bin/python test_xray_block.py 2>&1 | tee test_output.txt
                                # Fail pipeline if any test FAILED
                                if grep -q "FAILED" test_output.txt; then
                                    echo "❌ Some tests FAILED - check test_output.txt"
                                    exit 1
                                fi
                            """
                        } else {
                            bat """
                                set JFROG_URL=${JFROG_URL}
                                set JFROG_USER=%JFROG_USER%
                                set JFROG_PASS=%JFROG_PASS%
                                set XRAY_WAIT_SECS=30
                                ${VENV_DIR}\\Scripts\\python test_xray_block.py > test_output.txt 2>&1
                                type test_output.txt
                                findstr /C:"PASSED" test_output.txt
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
