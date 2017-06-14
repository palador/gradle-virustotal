package de.palador.gradle.vt

import com.kanishka.virustotalv2.VirusTotalConfig
import com.kanishka.virustotalv2.VirustotalPublicV2
import com.kanishka.virustotalv2.VirustotalPublicV2Impl
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.TaskAction
import java.io.File

open class VirusTotalReportTask : DefaultTask() {

    private val config = project.convention.getByType(VirusTotalExtensions::class.java)

    init {
        project.afterEvaluate {
            inputs.files(config.files)
        }
    }

    private val db = Database(
            logger,
            File(project.gradle.gradleUserHomeDir, VirusTotalScanTask::class.java.name)
                    .also { it.mkdirs() })

    @TaskAction
    fun run() {
        val files = config.files ?: throw NullPointerException("files must be set")

        logger.lifecycle("Report")

        files.forEach { file ->
            val sha256 = file.sha256string()

            val report = db.readScanReport(sha256).let { report ->
                if (report == null)
                    "<no report available>"
                else {
                    val positives = report.scans?.filter { it.value.isDetected == true } ?: emptyMap()
                    if (positives.isEmpty())
                        "negative"
                    else {
                        "positive " + positives.entries.joinToString {
                            "\n    ${it.key} (${it.value.result})"
                        }
                    }
                }
            }

            logger.lifecycle("$file -> $report")
        }
    }
}