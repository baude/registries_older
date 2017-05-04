#!/bin/bash
set -euo pipefail
IFS=$'\n\t'
#set -x
#declare -a STR_RESULT
# Test Suite for registry YAML parsing
STR_RESULT[0]=' --block_registries registry3 --insecure_registries registry2 --registries registry1'
JSON_RESULT[0]='{"block_registries":["registry3"],"insecure_registries":["registry2"],"secure_registries":["registry1"]}'

STR_RESULT[1]=' --block_registries registry3 --insecure_registries registry2 --registries registry1 --registries registry1a'
JSON_RESULT[1]='{"block_registries":["registry3"],"insecure_registries":["registry2"],"secure_registries":["registry1","registry1a"]}'

STR_RESULT[2]=' --registries registry1 --registries registry1a'
JSON_RESULT[2]='{"secure_registries":["registry1","registry1a"]}'

STR_RESULT[3]=' --registries registry1 --registries registry1a'
JSON_RESULT[3]='{"secure_registries":["registry1","registry1a"]}'

STR_RESULT[4]=' --registries registry1 --registries registry1a'
JSON_RESULT[4]='{"secure_registries":["registry1","registry1a"]}'

JSON_RESULT5='{}'

#TEST99
#test/test99.yaml is invalid YAML

PWD=$(pwd)
TEST_DIR="${PWD}/test"
BINARY="${PWD}/registries"
##echo ${PWD}
##echo ${STR_RESULT[*]}
counter=0;
error=0;
space="     "
echo "Running tests..."

for i in "${STR_RESULT[@]}"; do
	RESULT=$("${BINARY}" -i "${TEST_DIR}/test$counter.yaml")
	if [[ "${i}" != "${RESULT}" ]]; then
		echo "${space} STR_TEST${counter} failed"
		error=1
	else
		echo "${space} STR_TEST${counter} passed"
	fi

	RESULT=$("${BINARY}" -j -i "${TEST_DIR}/test$counter.yaml")

	if [[ "${JSON_RESULT[counter]}" != "${RESULT}" ]]; then
		echo "${space} JSON_TEST${counter} failed"
		error=1
	else
		echo "${space} JSON_TEST${counter} passed"
	fi

	counter=$((counter+1))

done

set +e

RESULT=$("${BINARY}" -i "${TEST_DIR}/test99.yaml")

if [[ $? -eq 0 ]]; then
	error=1
	echo "${space} Test 99 should have failed"
else
	echo "${space} Test 99 passed"
fi
	

set -e

if [[ "${error}" -eq 0 ]]; then
	echo "Tests passed... "
	exit 0
else
	echo "Tests failed... "
	exit 1
fi
