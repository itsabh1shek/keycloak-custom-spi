#!/bin/bash
mvn clean install
docker build -t itsabhishek/keycloak-custom-spi .
docker-compose up -d