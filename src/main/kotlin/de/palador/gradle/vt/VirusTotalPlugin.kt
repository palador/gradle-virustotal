package de.palador.gradle.vt

import org.gradle.api.Plugin
import org.gradle.api.Project

open class VirusTotalPlugin : Plugin<Project> {
    override fun apply(project: Project?) {
        project ?: throw NullPointerException("project")

        project.extensions.create("virustotal", VirusTotalExtensions::class.java)

        project.task(mapOf(
                "type" to VirusTotalScanTask::class.java,
                "group" to "Virus Total",
                "description" to "Perform scan at virustotal.com ."
        ), "virustotalScan")
        project.task(mapOf(
                "type" to VirusTotalReportTask::class.java,
                "group" to "Virus Total",
                "description" to "Shows results of the last scan."
        ), "virustotalReport")
    }
}
