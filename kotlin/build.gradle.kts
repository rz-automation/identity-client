// Kotlin backend SDK for the shared `identity` auth service: the JVM sibling of
// `../python`. Same contract (../CONTRACT.md), same security invariants, a
// dependency-light core (no web framework, no HTTP client beyond the JDK's own)
// so any JVM backend can depend on it.
//
// Published via JitPack from the repo tag. The consumer coordinate is
//   com.github.rz-automation.identity-client:kotlin:<git-tag>
// (the `kotlin/` subfolder is the JitPack module; `../jitpack.yml` drives the
// subfolder build). Verify the exact coordinate on the first published tag.

plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.serialization") version "2.2.21"
    `maven-publish`
}

// Coordinate matches what JitPack serves for this repo: it maps a single-artifact
// build to `com.github.rz-automation:identity-client:<git-tag>` regardless of the
// subfolder. Mirroring it here means a local publishToMavenLocal produces the
// exact same coordinate, so a consumer resolves identically online and offline.
// JitPack overrides `version` with the git tag at publish time.
group = "com.github.rz-automation"
version = "0.13.0"

kotlin {
    jvmToolchain(17)
}

repositories {
    mavenCentral()
}

val jjwtVersion = "0.12.6"

dependencies {
    // jjwt's Claims type is returned from the public verify() API, so it is `api`.
    api("io.jsonwebtoken:jjwt-api:$jjwtVersion")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:$jjwtVersion")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:$jjwtVersion")

    // Internal JSON parsing only (JWKS + response bodies); not exposed to callers.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation(kotlin("test"))
}

java {
    withSourcesJar()
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "identity-client"
            from(components["java"])
        }
    }
}
