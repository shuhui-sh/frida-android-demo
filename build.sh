#!/usr/bin/env bash
set -euo pipefail

if [ -n "${JDK17:-}" ]; then
    ./gradlew "-Dorg.gradle.java.home=${JDK17}" "$@"
else
    ./gradlew "$@"
fi
