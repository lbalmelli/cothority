#!/usr/bin/env bash

DBG_TEST=2
# Debug-level for app
DBG_APP=2
DBG_SRV=2
NBR_SERVERS=5

. $(go env GOPATH)/src/github.com/dedis/onet/app/libtest.sh

main(){
    startTest
    buildConode github.com/dedis/cothority/omniledger
	test Create
    #test Evolve
    #test NewEpoch
    stopTest
}

testCreate(){
    runCoBG 1 2 3 4
	
    testFail run create
	testFail run create -shards
	testFail run create -shards 0
	testFail run create -shards 1
	testFail run create -shards 1 -epoch
	testFail run create -shards 1 -epoch 500
	testOK run create -shards 1 -epoch 500 public.toml
}

testEvolve(){
	runCoBG 1 2
	testOK run create -shards 2 -epoch 10 roster.toml
	testFail run evolve 
	testFail run evolve ol.cfg
	testFail run evolve ol.cfg key.cfg
	testOK run evolve ol.cfg key.cfg newroster.toml
}

testNewEpoch(){
	runCoBG 1 2
	testOK run create -shards 2 -epoch 10 roster.toml
	testFail run newepoch 
	testFail run newepoch ol.cfg
	testOK run newepoch ol.cfg key.cfg
}

run(){
    dbgRun ./$APP -d $DBG_APP $@
}

main