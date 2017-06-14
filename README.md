# gradle-virustotal
Gradle plugin which allows to check files at virustotal.com .

## Configuration

*gradle.properties:*
```properties
vtApiKey=<YOUR API KEY>
```

*build.gradle:*
```groovy
buildscript {
    repositories {
        maven {
            url "https://raw.github.com/palador/maven/master/"
        }
        mavenCentral()
    }

    dependencies {
        classpath 'de.palador.gradle:gradle-virustotal:1.0-SNAPSHOT'
    }
}

sourceCompatibility = 1.8

apply plugin: 'de.palador.gradle-virustotal'

virustotal {
    apikey = "$vtApiKey"
    files = fileTree(dir: "${buildDir}/myDistro")
            .include("**/*.exe")
    rescanThresholdDays = 1
}
...
```

## Usage

To scan all given files at [https://virustotal.com], use:

    gradle virustotalScan

To list previous scan reports (which are cached at you gradle home directory), use:

    gradle virustotalReport
