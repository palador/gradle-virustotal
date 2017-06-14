package de.palador.gradle.vt

import com.kanishka.virustotal.dto.FileScanReport
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

        logger.lifecycle("Reports")

        data class Entry(
                val file: File,
                val sha: String,
                val report: FileScanReport?)

        val reports = files
                .map {
                    val sha = it.sha256string()
                    Entry(it, sha, db.readScanReport(sha))
                }
                .sortedWith(compareBy({ it.report?.positives }, { it.file.absolutePath }))
                .groupBy {
                    when {
                        it.report == null -> ReportStatus.NOT_AVAILABLE
                        it.report.positives == 0 -> ReportStatus.NEGATIVE
                        else -> ReportStatus.POSITIVE
                    }
                }

        reports.keys.toList().sorted().forEach { status ->
            val statusName = when (status) {
                VirusTotalReportTask.ReportStatus.NOT_AVAILABLE -> "Missing Reports"
                VirusTotalReportTask.ReportStatus.POSITIVE -> "Positive Reports"
                VirusTotalReportTask.ReportStatus.NEGATIVE -> "Negative Reports"
            }
            val entries = reports[status] ?: emptyList()

            logger.lifecycle("")
            logger.lifecycle("")
            logger.lifecycle("** $statusName (${entries.size}) **")
            entries.forEachIndexed { index, entry ->
                logger.lifecycle("")
                logger.lifecycle("${String.format("%-4s", "${index + 1}:")}${entry.file}")
                logger.lifecycle("    sha256:     ${entry.sha}")
                entry.report?.also { report ->
                    logger.lifecycle("    last scan:  ${report.scanDate ?: "unknown"}")
                    logger.lifecycle("    link:       ${report.permalink ?: "unknwon"}")
                    logger.lifecycle("    positive:   ${report.positives} / ${report.total}")
                    val scansWithResults = report.scans.filter { it.value?.result != null }
                    if (!scansWithResults.isEmpty()) {
                        logger.lifecycle("    scans with results:")
                        scansWithResults.forEach {
                            logger.lifecycle(String.format("      %-9s %s", "${it.key}:", it.value.result))
                        }
                    }
                }
            }
        }
    }

    private enum class ReportStatus {
        NOT_AVAILABLE, POSITIVE, NEGATIVE
    }
}