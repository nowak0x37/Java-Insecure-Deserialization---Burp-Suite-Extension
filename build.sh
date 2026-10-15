#!/bin/sh
set -e
API_JAR="${1:-/tmp/montoya-api.jar}"
mkdir -p build/classes dist
javac -cp "$API_JAR" -d build/classes \
  src/javaser/JavaSerializationProtocol.java \
  src/burp/javaobjectmodify/JavaObjectModifyExtension.java
cp -r src/burp/META-INF build/
(cd build/classes && jar --create --file ../../dist/java-object-modify-0.1.0.jar . ../META-INF)
echo "Built dist/java-object-modify-0.1.0.jar"
