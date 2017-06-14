package de.palador.gradle.vt

object VirusTotalResponseCodes {
    object Scan {
        val error = 0
        val queued = 1
    }

    object Rescan {
        val queued = 1
        val notPresent = 0
        val error = -1
    }

    object Report {
        val stillQueued = -2
        val error = -1
        val notPresent = 0
        val present = 1
    }
}
