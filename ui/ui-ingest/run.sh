#!/bin/bash

mkdir -p target/src/main
rm -rf target/src/main/config
cp -r src/main/config target/src/main/config

#retrieve version
version="$(grep -oP '(?<=>).*?(?=</version>)' pom.xml | grep -v 'version')"

java -jar target/ui-ingest-$(echo $version).jar -Xms128m -Xmx512m --spring.profiles.active=dev,recette
