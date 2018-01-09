#!/usr/bin/env bash

set -ex

go get -t ./...
if [ ${TESTMODE} == "unit" ]; then
  ginkgo -r -v -cover -randomizeAllSpecs -randomizeSuites -trace -skipPackage integrationtests,benchmark
fi

if [ ${TESTMODE} == "integration" ]; then
  # run integration tests
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -trace -race integrationtests/chrome
  # ginkgo -r -v -randomizeAllSpecs -randomizeSuites -trace integrationtests
fi
