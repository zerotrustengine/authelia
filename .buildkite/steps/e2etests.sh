#!/usr/bin/env bash
set -eu

PARALLEL=""

for SUITE_NAME in $(authelia-scripts suites list); do
if [[ "${SUITE_NAME}" =~ ^(HighAvailability|Standalone)$ ]]; then
  PARALLEL=" --parallel 5"
fi
cat << EOF
  - label: ":selenium: ${SUITE_NAME} Suite"
    command: "authelia-scripts --log-level debug suites test ${SUITE_NAME}${PARALLEL} --headless"
    retry:
      automatic: true
EOF
if [[ "${SUITE_NAME}" = "ActiveDirectory" ]]; then
cat << EOF
    agents:
      suite: "activedirectory"
EOF
elif [[ "${SUITE_NAME}" = "HighAvailability" ]]; then
cat << EOF
    agents:
      suite: "highavailability"
EOF
elif [[ "${SUITE_NAME}" = "Kubernetes" ]]; then
cat << EOF
    agents:
      suite: "kubernetes"
EOF
elif [[ "${SUITE_NAME}" = "Standalone" ]]; then
cat << EOF
    agents:
      suite: "standalone"
EOF
else
cat << EOF
    agents:
      suite: "all"
EOF
fi
cat << EOF
    env:
      SUITE: "${SUITE_NAME}"
EOF
done