.PHONY: build push

VERSION ?= $(shell git describe --always --dirty --abbrev=0)
IMAGE ?= gcr.io/heptio-images/ironclad

build:
	docker build --build-arg "IRONCLAD_VERSION=$(VERSION)" -t "$(IMAGE):$(VERSION)" .

push: build
	docker push "$(IMAGE):$(VERSION)"
