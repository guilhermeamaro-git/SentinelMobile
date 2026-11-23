package com.sentinel.mobile

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.TrustManagerFactory

fun describeError(e: Exception): String = when (e) {
    is SSLException -> "TLS falhou (certificado/SAN/IP): ${e.message}"
    is SocketTimeoutException -> "timeout"
    is ConnectException -> "conexao recusada/inalcancavel"
    is UnknownHostException -> "host desconhecido"
    else -> "${e.javaClass.simpleName}: ${e.message}"
}

object Http {
    class Resp(val code: Int, val body: String)

    private var cached: SSLContext? = null

    /** Confia SOMENTE no certificado embutido em res/raw (pinning). A validacao de hostname/SAN continua ativa. */
    @Synchronized
    private fun ssl(app: Context): SSLContext {
        cached?.let { return it }
        val cert = app.resources.openRawResource(R.raw.sentinel_cert).use {
            CertificateFactory.getInstance("X.509").generateCertificate(it)
        }
        val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("sentinel", cert)
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
        val c = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
        cached = c
        return c
    }

    @Throws(IOException::class)
    fun call(app: Context, method: String, path: String, json: String?, auth: Boolean = true): Resp {
        if (Prefs.simOffline) throw IOException("rede simulada offline")
        val c = URL(Prefs.baseUrl + path).openConnection()
        if (c !is HttpsURLConnection) throw IOException("URL deve comecar com https://")
        try {
            c.sslSocketFactory = ssl(app).socketFactory
            c.connectTimeout = 5000      // timeout do handshake TCP
            c.readTimeout = 8000         // timeout de espera pela resposta
            c.requestMethod = method
            c.useCaches = false
            c.setRequestProperty("Accept", "application/json")
            if (auth) {
                c.setRequestProperty("Authorization", "Bearer " + Prefs.token)
                c.setRequestProperty("X-Device-Id", Prefs.deviceId)
            }
            if (json != null) {
                val bytes = json.toByteArray(Charsets.UTF_8)
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                c.outputStream.use { it.write(bytes) }
            }
            val code = c.responseCode
            val stream = if (code in 200..399) c.inputStream else c.errorStream
            val body = stream?.bufferedReader()?.use { it.readText() } ?: ""
            return Resp(code, body)
        } finally {
            c.disconnect()
        }
    }
}

/** Fila persistente em arquivo + retry com backoff exponencial. Envio sempre passa por aqui. */
object Outbox {
    private class Item(val id: String, val path: String, val body: String, var attempts: Int = 0, var nextAt: Long = 0)

    private val items = ArrayList<Item>()
    private lateinit var file: File
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
    @Volatile var lastStatus = "-"

    @Synchronized
    fun init(ctx: Context) {
        file = File(ctx.filesDir, "outbox.json")
        try {
            if (file.exists()) {
                val arr = JSONArray(file.readText())
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    items.add(Item(o.getString("id"), o.getString("path"), o.getString("body"), o.optInt("attempts")))
                }
            }
        } catch (e: Exception) {
            AppLog.add("Fila corrompida, reiniciada: ${e.message}")
            items.clear()
        }
    }

    @Synchronized
    private fun save() {
        try {
            val arr = JSONArray()
            items.forEach {
                arr.put(JSONObject().put("id", it.id).put("path", it.path).put("body", it.body).put("attempts", it.attempts))
            }
            val tmp = File(file.parentFile, "outbox.tmp")
            tmp.writeText(arr.toString())
            if (!tmp.renameTo(file)) { file.delete(); tmp.renameTo(file) }
        } catch (e: Exception) {
            AppLog.add("Falha ao salvar fila: ${e.message}")
        }
    }

    @Synchronized fun size() = items.size

    @Synchronized
    fun add(path: String, body: String) {
        items.add(Item(UUID.randomUUID().toString(), path, body))
        save()
    }

    @Synchronized
    private fun nextReady(): Item? {
        val now = System.currentTimeMillis()
        return items.firstOrNull { it.nextAt <= now }
    }

    @Synchronized
    private fun remove(it: Item) { items.remove(it); save() }

    @Synchronized
    private fun backoff(it: Item, why: String) {
        it.attempts++
        val delay = minOf(30_000L, 1000L shl minOf(it.attempts, 10))   // 2s,4s,8s,16s,30s...
        it.nextAt = System.currentTimeMillis() + delay
        save()
        lastStatus = "falha (${it.attempts}x) retry em ${delay / 1000}s"
        AppLog.add("Envio ${it.path} falhou: $why -> retry em ${delay / 1000}s")
    }

    /** Chamado a cada 1 s pelo agendador. Envia tudo que estiver pronto; para no 1o erro de rede. */
    fun pump(app: Context) {
        while (true) {
            val it = nextReady() ?: return
            try {
                val r = Http.call(app, "POST", it.path, it.body)
                val stamp = fmt.format(Date())
                when {
                    r.code in 200..299 -> {
                        remove(it)
                        lastStatus = "OK ${it.path.substringAfterLast('/')} ${r.code} $stamp"
                        AppLog.add("Enviado ${it.path} (HTTP ${r.code})")
                    }
                    // 401 nao descarta: o alerta deve sobreviver ate o aparelho ser (re)pareado.
                    r.code in 400..499 && r.code != 401 && r.code != 408 && r.code != 429 -> {
                        remove(it)   // erro do cliente: repetir nao adianta
                        lastStatus = "DESCARTADO ${r.code} $stamp"
                        AppLog.add("Descartado ${it.path}: HTTP ${r.code} ${r.body.take(120)}")
                    }
                    else -> { backoff(it, "HTTP ${r.code}"); return }
                }
            } catch (e: IOException) {
                backoff(it, describeError(e)); return
            }
        }
    }
}