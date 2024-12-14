PKG?=github.com/hakwerk/labca/gui
BINNAME?=labca-gui

# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
PREFIX?=
TAG=$(shell git rev-list --tags --max-count=1)
VERSION=$(shell git describe --always --tags $(TAG))
DEB_VERSION=$(shell echo $(VERSION) | sed 's/^v//' | sed 's/-/./g')
RELEASE=./release

all: build

.PHONY: all

ifdef V
$(info     VERSION is $(VERSION))
$(info DEB_VERSION is $(DEB_VERSION))
endif

#########################################
# Build
#########################################

LDFLAGS := -ldflags='-w -X "main.standaloneVersion=$(VERSION)" -extldflags "-static"'

download:
	$Q cd gui; \
	go mod download; \
	cd ..

build: $(PREFIX)bin/$(BINNAME)
	@echo "Build Complete!"

$(PREFIX)bin/$(BINNAME): download $(call rwildcard,*.go)
	$Q mkdir -p $(@D)
	$Q cd gui; \
	$(GOOS_OVERRIDE) $(GOFLAGS) go build -o ../$(PREFIX)bin/$(BINNAME) $(LDFLAGS) $(PKG); \
	cd ..

.PHONY: download build

#########################################
# Install
#########################################

INSTALL_PREFIX?=/usr/

install: $(PREFIX)bin/$(BINNAME)
	$Q install -D $(PREFIX)bin/$(BINNAME) $(DESTDIR)$(INSTALL_PREFIX)bin/$(BINNAME)

uninstall:
	$Q rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(BINNAME)

.PHONY: install uninstall

#########################################
# Debian
#########################################

changelog:
	$Q echo "labca-gui ($(DEB_VERSION)) unstable; urgency=medium" > debian/changelog
	$Q echo >> debian/changelog
	$Q echo "  * See https://github.com/hakwerk/labca/releases" >> debian/changelog
	$Q echo >> debian/changelog
	$Q echo " -- hakwerk <github@hakwerk.com>  $(shell date -uR)" >> debian/changelog

debian: changelog
	$Q mkdir -p $(RELEASE); \
	OUTPUT=../labca-gui*.deb; \
	rm -f $$OUTPUT; \
	dpkg-buildpackage -b -rfakeroot -us -uc && cp $$OUTPUT $(RELEASE)/

debian-arm64: changelog
	$Q mkdir -p $(RELEASE); \
	OUTPUT=../labca-gui*.deb; \
	rm -f $$OUTPUT; \
	GOOS_OVERRIDE="GOARCH=arm64" \
	dpkg-buildpackage -b -rfakeroot -us -uc --host-arch arm64 && cp $$OUTPUT $(RELEASE)/

distclean: clean

.PHONY: changelog debian debian-arm64 distclean

#########################################
# Clean
#########################################

clean:
ifneq ($(BINNAME),"")
	$Q rm -f $(PREFIX)bin/$(BINNAME)
endif

.PHONY: clean

#########################################
# Dev
#########################################

run:
	$Q cd gui && go run -ldflags='-X "main.standaloneVersion=$(shell git describe --always --tags HEAD)"' github.com/hakwerk/labca/gui --config stepca_config.json; cd ..

.PHONY: run
