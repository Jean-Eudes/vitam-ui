#!/bin/bash

#retrieve version
version="$(grep -oP '(?<=>).*?(?=</version>)' pom.xml | grep -v 'version')"

java -jar target/ui-referential-$(echo $version).jar -Xms128m -Xmx512m --spring.profiles.active=dev,recette
