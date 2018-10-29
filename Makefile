
.PHONY: pebble pebble_start pebble_wait pebble_test pebble_stop boulder boulder_setup boulder_start boulder_test boulder_stop


GOPATH ?= $(HOME)/go
BOULDER_PATH ?= $(GOPATH)/src/github.com/letsencrypt/boulder
PEBBLE_TAG ?= 2018-10-10


pebble: pebble_start pebble_wait pebble_test pebble_stop

# runs an instance of pebble using docker
pebble_start:
	docker run -d --name pebble -p 14000:14000 -e "PEBBLE_VA_ALWAYS_VALID=1" letsencrypt/pebble:$(PEBBLE_TAG) pebble -strict

# waits until pebble responds
pebble_wait:
	while ! wget --delete-after -q --no-check-certificate "https://localhost:14000/dir" ; do sleep 1 ; done

# tests the code against a running pebble instance
pebble_test:
	ACME_SERVER=pebble GOCACHE=off go test github.com/eggsampler/acme

# stops the running pebble instance
pebble_stop:
	docker stop pebble
	-docker rm pebble


boulder: boulder_setup boulder_start boulder_wait boulder_test boulder_stop

boulder_setup:
	mkdir -p BOULDER_PATH
	git clone --depth 1 https://github.com/letsencrypt/boulder.git $(BOULDER_PATH) 2> /dev/null \
		|| (cd $(BOULDER_PATH); git reset --hard HEAD && git pull -q)
	sed -i -e 's/--http01 ""/--http01 :5002/' $(BOULDER_PATH)/test/startservers.py
	sed -i -e 's/test\/config$$/test\/config-next/' $(BOULDER_PATH)/docker-compose.yml

# runs an instance of boulder
# NB: this edits test/startservers.py and docker-compose.yml
boulder_start:
	docker-compose -f $(BOULDER_PATH)/docker-compose.yml up -d

# waits until boulder responds
boulder_wait:
	while ! wget --delete-after -q --no-check-certificate "http://localhost:4001/directory" ; do sleep 1 ; done

# tests the code against a running boulder instance
boulder_test:
	ACME_SERVER=boulder GOCACHE=off go test github.com/eggsampler/acme

# stops the running docker instance
boulder_stop:
	docker-compose -f $(BOULDER_PATH)/docker-compose.yml down