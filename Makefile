SERVICE := bouncer-policies

-include Makefile.env

DOCKER ?= docker

BASE_IMAGE_NAME := docker.io/openpolicyagent/opa
BASE_IMAGE_TAG := 0.26.0

.PHONY: manifest test repl

VALIDATOR := $(CURDIR)/validator.escript
INSTANCES := $(shell find test/test/service -type f -path '*/fixtures/*/*.json')
ifeq ($(INSTANCES),)
$(error No fixtures to validate found, you probably need to update a search pattern)
endif

.PHONY: $(VALIDATOR)

INSTANCE_TARGETS := $(foreach inst, $(INSTANCES), $(inst).validate)
%.validate: %
	$(VALIDATOR) $^

validate: $(VALIDATOR) $(INSTANCE_TARGETS)

MANIFEST := $(CURDIR)/policies/.manifest
REVISION := $(SERVICE_IMAGE_TAG)

manifest: $(MANIFEST)

$(MANIFEST): $(MANIFEST).src
	jq '.revision = "$(REVISION)"' $< > $@

$(VALIDATOR):
	$(MAKE) TARGET=$(VALIDATOR) -C validator

TEST_IMAGE := $(BASE_IMAGE_NAME):$(BASE_IMAGE_TAG)
TEST_BUNDLES := policies test
TEST_VOLUMES := $(foreach bundle, $(TEST_BUNDLES), -v $(CURDIR)/$(bundle):/$(bundle):ro)
TEST_BUNDLE_DIRS := $(foreach bundle, $(TEST_BUNDLES), /$(bundle))
TEST_COVERAGE_THRESHOLD := 99

TEST_CMD := $(DOCKER) run --rm $(TEST_VOLUMES) $(TEST_IMAGE) test $(TEST_BUNDLE_DIRS)

test: manifest
	$(TEST_CMD) \
		--explain full \
		--ignore input.json

run-%:
	$(TEST_CMD) \
		--explain full \
		--ignore input.json \
		-v \
		--run $*

test-coverage: manifest
	python3 test_coverage.py "$(TEST_CMD) --coverage" $(TEST_COVERAGE_THRESHOLD)

repl: manifest
	$(DOCKER) run --rm -it -v $$PWD:$$PWD --workdir $$PWD $(TEST_IMAGE) run --watch --bundle policies --bundle test

