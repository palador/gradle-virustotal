package de.palador.gradle.vt

import org.gradle.api.file.FileCollection

open class VirusTotalExtensions {

    var apikey: String? = null

    var files: FileCollection? = null

    /* default: 1 */
    var rescanThresholdDays: Int? = null

    /*
     * default: 32.0
     *
     * 1MB != 1MiB -> 1MB == 1000 * 1000B
     */
    var maxFileSizeMB: Double? = null

}