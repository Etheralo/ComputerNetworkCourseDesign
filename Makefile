PYTHON ?= python3
HOST ?= 127.0.0.1
PORT ?= 5353
UPSTREAM ?= 8.8.8.8
UPSTREAM_PORT ?= 53

.PHONY: run test demo socket-server socket-client check

run:
	$(PYTHON) -m src.dns_relay.server --host $(HOST) --port $(PORT) --upstream $(UPSTREAM) --upstream-port $(UPSTREAM_PORT) --table config/dnsrelay.txt

test:
	$(PYTHON) -m unittest discover -s tests -v

demo:
	$(PYTHON) -m src.dns_relay.demo

socket-server:
	$(PYTHON) -m src.socket_demo.server --host 127.0.0.1 --port 9000

socket-client:
	$(PYTHON) -m src.socket_demo.client --host 127.0.0.1 --port 9000

check: test demo
