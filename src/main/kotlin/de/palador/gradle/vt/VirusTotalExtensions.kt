package de.palador.gradle.vt

import org.gradle.api.file.FileCollection

open class VirusTotalExtensions {

    var apikey : String? = null
    var files: FileCollection? = null
    var rescanThresholdDays: Int? = null

}