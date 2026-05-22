#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_JAR="${1:-/tmp/ts-travel-service-1.0.jar}"
BUILD_DIR="$ROOT_DIR/build"
WORK_DIR="$BUILD_DIR/work"
CLASSES_DIR="$BUILD_DIR/classes"
OUT_JAR="$BUILD_DIR/xmark-propagation.jar"

if [[ ! -f "$SERVICE_JAR" ]]; then
  cid="$(docker create codewisdom/ts-travel-service:0.2.0)"
  trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
  docker cp "$cid:/app/ts-travel-service-1.0.jar" "$SERVICE_JAR"
  docker rm "$cid" >/dev/null
  trap - EXIT
fi

rm -rf "$WORK_DIR" "$CLASSES_DIR"
mkdir -p "$WORK_DIR" "$CLASSES_DIR"

(
  cd "$WORK_DIR"
  jar xf "$SERVICE_JAR" BOOT-INF/lib
)

CLASSPATH="$(find "$WORK_DIR/BOOT-INF/lib" -name '*.jar' -print | tr '\n' ':')"

javac --release 8 \
  -proc:none \
  -cp "$CLASSPATH" \
  -d "$CLASSES_DIR" \
  $(find "$ROOT_DIR/src/main/java" -name '*.java' -print)

mkdir -p "$CLASSES_DIR/META-INF"
cp "$ROOT_DIR/src/main/resources/META-INF/spring.factories" "$CLASSES_DIR/META-INF/spring.factories"

jar cf "$OUT_JAR" -C "$CLASSES_DIR" .
echo "$OUT_JAR"
