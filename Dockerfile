# Copyright 2017 Heptio Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.10-alpine3.7 AS build
RUN mkdir -p /go/src/github.com/heptiolabs/ironclad
COPY ./vendor /go/src/github.com/heptiolabs/ironclad/vendor
COPY ./cmd /go/src/github.com/heptiolabs/ironclad/cmd
COPY ./pkg /go/src/github.com/heptiolabs/ironclad/pkg
RUN go install -v github.com/heptiolabs/ironclad/cmd/ironclad

FROM alpine:3.7

# this is passed in from the Makefile
ARG IRONCLAD_VERSION

################################################################################
# 0. libModSecurity
################################################################################

# libModSecurity source repo and tag/branch
ARG LIBMODSECURITY_REPO=https://github.com/SpiderLabs/ModSecurity
ARG LIBMODSECURITY_VERSION=v3.0.2

# download, compile, and install libmodååsecurity
WORKDIR /tmp/libmodsecurity
COPY build/install-libmodsecurity .
RUN ./install-libmodsecurity && rm -rvf /tmp/libmodsecurity

################################################################################
# 1. Nginx and ModSecurity-nginx
################################################################################

# ModSecurity-nginx connector module source repo and tag/branch
ARG MODSECURITY_NGINX_REPO=https://github.com/SpiderLabs/ModSecurity-nginx
ARG MODSECURITY_NGINX_VERSION=37b76e88df4bce8a9846345c27271d7e6ce1acfb

# Nginx source URL
ARG NGINX_URL=https://nginx.org/download/nginx-1.14.0.tar.gz

# download, compile, and install nginx and the ModSecurity-nginx connector module
WORKDIR /tmp/nginx
COPY build/install-nginx .
RUN ./install-nginx && rm -rvf /tmp/nginx

################################################################################
# 2. OWASP ModSecurity Core Rule Set (CRS)
################################################################################

# CRS source repo and tag/branch
ARG MODSECURITY_CRS_REPO=https://github.com/SpiderLabs/owasp-modsecurity-crs.git
ARG MODSECURITY_CRS_VERSION=v3.0.2

# download and unpack the OWASP ModSecurity Core Rule Set (CRS)
WORKDIR /tmp/crs
COPY build/install-crs .
RUN ./install-crs && rm -rvf /tmp/crs

################################################################################
# 3. MaxMind GeoIP databases
################################################################################

# MaxMind GeoIP database download URLs
# this is the free city-level database in the older legacy format supported by ModSecurity (~12 MB zipped)
ARG MAXMIND_GEOIP_LEGACY_URL=https://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz

# this is the free city-level database in the newer format supported by github.com/oschwald/geoip2-golang (~26 MB zipped)
ARG MAXMIND_GEOIP_CITY_URL=https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz

# this is the free ASN (autonomous system number) database (~3 MB zipped)
ARG MAXMIND_GEOIP_ASN_URL=https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz

# download and install the MaxMind GeoIP database
WORKDIR /tmp/geoip-dat
COPY build/install-geoip-dat .
RUN ./install-geoip-dat && rm -rvf /tmp/geoip-dat

################################################################################
# 4. Final configuration
################################################################################

# set up our configuration files for nginx and modsecurity
WORKDIR /
COPY build/modsecurity.conf /etc/nginx/conf/modsecurity.conf

# copy in the main binary and set it as the entry point
COPY --from=build /go/bin/ironclad /usr/local/bin/ironclad
ENTRYPOINT ["/usr/local/bin/ironclad"]
CMD ["/usr/local/bin/ironclad"]
