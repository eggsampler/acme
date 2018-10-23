.PHONY: pebble_run pebble_test boulder_run boulder_test

# runs an instance of pebble using docker
PEBBLE_TAG ?= 2018-10-10
pebble_run:
	docker run -p 14000:14000 -e "PEBBLE_VA_ALWAYS_VALID=1" letsencrypt/pebble:$(PEBBLE_TAG) pebble -strict

# tests the code against a running pebble instance
pebble_test:
	ACME_SERVER=pebble GOCACHE=off go test github.com/eggsampler/acme

# runs an instance of boulder
# NB: this edits test/startservers.py and docker-compose.yml
BOULDER_PATH ?= $(GOPATH)/src/github.com/letsencrypt/boulder
boulder_run:
	sed -i -e 's/--http01 ""/--http01 :5002/' $(BOULDER_PATH)/test/startservers.py
	sed -i -e 's/test\/config$$/test\/config-next/' $(BOULDER_PATH)/docker-compose.yml
	docker-compose -f $(BOULDER_PATH)/docker-compose.yml up

# tests the code against a running boulder instance
boulder_test:
	ACME_SERVER=boulder GOCACHE=off go test github.com/eggsampler/acme