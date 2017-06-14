package de.palador.gradle.vt

import com.kanishka.virustotal.dto.FileScanReport
import com.kanishka.virustotalv2.VirusTotalConfig
import com.kanishka.virustotalv2.VirustotalPublicV2
import com.kanishka.virustotalv2.VirustotalPublicV2Impl
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.nio.file.Files
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit

open class VirusTotalScanTask : DefaultTask() {

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
        val apikey = config.apikey ?: throw NullPointerException("apikey must be set")
        val files = config.files?.toList() ?: throw NullPointerException("files must be set")

        VirusTotalConfig.getConfigInstance()
                .virusTotalAPIKey = apikey
        val vtApi: VirustotalPublicV2 = VirustotalPublicV2Impl()

        files.forEachIndexed { index, file ->
            val sha256 = file.sha256string()

            logger.lifecycle("")
            logger.lifecycle("process file ${index + 1}/${files.size}")
            logger.lifecycle("    $file")
            logger.lifecycle("    ($sha256)")

            val sizeMB = Files.size(file.toPath()).toDouble() / (1000.0 * 1000.0)
            logger.lifecycle("    ${String.format("%.3f MB", sizeMB)}")
            if (sizeMB > (config.maxFileSizeMB ?: 32.0)) {
                logger.lifecycle("    ignore file, because it's too big")
                return@forEachIndexed
            }

            val cachedScanInfo = db.getScanInfo(sha256)
            val cachedScanReport = db.readScanReport(sha256)
            val isScanReportOutdated = cachedScanReport == null
                    || cachedScanReport.responseCode != VirusTotalResponseCodes.Report.present
                    || cachedScanReport.scanDate
                    ?.let { SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(it) }
                    .let {
                        if (it == null) true
                        else {
                            val daysSinceLast = TimeUnit.MILLISECONDS.toDays(
                                    System.currentTimeMillis() - it.time)
                            daysSinceLast > (config.rescanThresholdDays?.toLong() ?: 1L)
                        }
                    }

            if (!isScanReportOutdated) {
                logger.lifecycle("    scan report is still up to date")
            } else {
                val latestScanInfo =
                        if (cachedScanInfo != null
                                && cachedScanInfo.responseCode == VirusTotalResponseCodes.Scan.queued) {
                            val scanInfo = vtApi.run("rescan", logger) { reScanFiles(arrayOf(cachedScanInfo.resource)) }
                                    ?.firstOrNull()
                            if (scanInfo != null && scanInfo.responseCode != VirusTotalResponseCodes.Rescan.queued) {
                                logger.info("    rescan failed, because virus total didn't found previously " +
                                        "uploaded file. upload it again...")
                                vtApi.run("scan", logger) { scanFile(file) }
                            } else {
                                scanInfo
                            }
                        } else {
                            logger.lifecycle("    upload file... this may take a while")
                            vtApi.run("scan", logger) { scanFile(file) }
                        }

                if (latestScanInfo == null)
                    logger.error("    failed to (re)scan file")
                else if (latestScanInfo.responseCode != VirusTotalResponseCodes.Scan.queued)
                    logger.error(
                            "    failed to (re)scan file: unexpected response code: ${latestScanInfo.responseCode}")
                else {
                    db.writeScanInfo(latestScanInfo, sha256)

                    logger.lifecycle("    request scan report...")

                    var scanReport: FileScanReport? = null
                    var lastResult: FileScanReport? = null
                    loop@ for (i in (0..10)) {
                        lastResult = vtApi.run("get scan report", logger) { getScanReport(latestScanInfo.resource) }
                        when (lastResult?.responseCode) {
                            VirusTotalResponseCodes.Report.error -> {
                                break@loop
                            }
                            null,
                            VirusTotalResponseCodes.Report.notPresent,
                            VirusTotalResponseCodes.Report.stillQueued -> {
                                Thread.sleep(20L * 1000L)
                            }
                            VirusTotalResponseCodes.Report.present -> {
                                scanReport = lastResult
                                break@loop
                            }
                        }
                    }

                    scanReport.also {
                        if (it != null) {
                            db.writeScanReport(it, sha256)
                            logger.lifecycle("    success... ${it.positives} of ${it.total} are positive")
                        } else {
                            logger.lifecycle("    ERROR")
                            lastResult?.also {
                                logger.lifecycle("        response code: ${it.responseCode}")
                                logger.lifecycle("        message:       ${it.verboseMessage}")
                            }
                        }
                    }
                }
            }
        }
    }
}