#!/usr/bin/env bash

set -ex

go get -t ./...
if [ ${TESTMODE} == "unit" ]; then
  ginkgo -r -v -cover -randomizeAllSpecs -randomizeSuites -trace -skipPackage integrationtests,benchmark
fi

if [ ${TESTMODE} == "integration" ]; then
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -noisyPendings=false -trace integrationtests/gquic
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -noisyPendings=false -trace integrationtests/gquic
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -noisyPendings=false -trace integrationtests/gquic
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -noisyPendings=false -trace integrationtests/gquic
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -noisyPendings=false -trace integrationtests/gquic
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -noisyPendings=false -trace integrationtests/gquic
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -noisyPendings=false -trace integrationtests/gquic
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -noisyPendings=false -trace integrationtests/gquic
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -noisyPendings=false -trace integrationtests/gquic
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -noisyPendings=false -trace integrationtests/gquic
  ginkgo -r -v -randomizeAllSpecs -randomizeSuites -noisyPendings=false -trace integrationtests/gquic
fi
