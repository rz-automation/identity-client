plugins {
    // Lets jvmToolchain(17) auto-provision a JDK if the host lacks one.
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}

rootProject.name = "identity-client-kotlin"
