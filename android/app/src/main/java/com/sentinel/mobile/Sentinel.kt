package com.sentinel.mobile

import android.content.Context
import android.util.Base64
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

object Sentinel {
    lateinit var app: Context
    @Volatile var cfg = Cfg()
    @Volatile var online = false
    @Volatile var netInfo = "aguardando"

    private val engine = RuleEngine()
    private val sched = Executors.newScheduledThreadPool(3)   // outbox, polling, config/localizacao
    private val work = Executors.newSingleThreadExecutor()     // eventos/alertas em ordem (estado consistente)
    private val sensors = Executors.newFixedThreadPool(2)      // GPS e camera em paralelo
    private var started = false
    private var locFailLogged = false

    private fun uuid() = UUID.randomUUID().toString()

    private fun safe(name: String, f: () -> Unit) = Runnable {
        try { f() } catch (t: Throwable) { AppLog.add("$name erro: ${t.javaClass.simpleName} ${t.message}") }
    }

    @Synchronized
    fun init(ctx: Context) {
        if (started) return
        started = true
        app = ctx.applicationContext
        Prefs.init(app)
        Outbox.init(app)
        sched.scheduleWithFixedDelay(safe("outbox") { Outbox.pump(app) }, 1, 1, TimeUnit.SECONDS)
        sched.scheduleWithFixedDelay(safe("poll") { poll() }, 2, 3, TimeUnit.SECONDS)
        sched.scheduleWithFixedDelay(safe("config") { fetchConfig() }, 3, 30, TimeUnit.SECONDS)
        sched.scheduleWithFixedDelay(safe("loc") { sendLocationNow() }, 5, 30, TimeUnit.SECONDS)
        AppLog.add("SentinelMobile iniciado")
    }

    // ------------------------------------------------------------ rede / comandos
    private fun poll() {
        try {
            val r = Http.call(app, "GET", "/api/v1/commands/poll", null)
            if (r.code != 200) {
                online = false
                netInfo = if (r.code == 401) "HTTP 401 (token do dispositivo errado?)" else "HTTP ${r.code}"
                return
            }
            online = true; netInfo = "ok"
            val c = JSONObject(r.body).optJSONObject("command") ?: return
            val id = c.getInt("id")
            val name = c.getString("command")
            AppLog.add("Comando remoto: $name (#$id)")
            when (name) {
                "LOCK" -> if (!Prefs.locked) LockManager.lock(app, "comando remoto")
                "UNLOCK" -> LockManager.unlock(app)
            }
            Http.call(app, "POST", "/api/v1/commands/$id/ack", "{}")   // sem ACK o servidor reentrega em 10 s
        } catch (e: IOException) {
            online = false; netInfo = describeError(e)
        } catch (e: JSONException) {
            netInfo = "JSON invalido do servidor"
        }
    }

    private fun fetchConfig() {
        try {
            val r = Http.call(app, "GET", "/api/v1/config", null)
            if (r.code != 200) return
            val j = JSONObject(r.body)
            val al = j.optJSONArray("AUTO_LOCK_RULES")
            val set = HashSet<String>()
            if (al != null) for (i in 0 until al.length()) set.add(al.getString(i))
            val n = Cfg(
                j.optInt("R1_MAX_FALHAS", 3), j.optInt("R1_JANELA_S", 120),
                j.optInt("R2_MAX_ACESSOS", 3), j.optInt("R2_JANELA_S", 120),
                j.optInt("R3_JANELA_S", 90), j.optInt("COOLDOWN_S", 30), set
            )
            if (n != cfg) { cfg = n; AppLog.add("Parametros atualizados do servidor") }
        } catch (e: Exception) { /* mantem os ultimos parametros conhecidos */ }
    }

    fun refreshNow() {
        sched.execute(safe("config") { fetchConfig() })
        sched.execute(safe("poll") { poll() })
    }

    fun testConnection() {
        sched.execute(safe("teste") {
            try {
                val h = Http.call(app, "GET", "/api/v1/health", null, auth = false)
                AppLog.add("TESTE health: HTTP ${h.code} (TLS + TCP ok)")
                val c = Http.call(app, "GET", "/api/v1/config", null)
                AppLog.add("TESTE auth: HTTP ${c.code}" + if (c.code == 401) " -> token errado" else " -> token ok")
            } catch (e: IOException) { AppLog.add("TESTE falhou: " + describeError(e)) }
        })
    }

    // ------------------------------------------------------------ localizacao
    fun sendLocationNow() {
        sensors.execute(safe("localizacao") {
            val fix = LocationHelper.getFix(app, 8000)
            if (fix == null) {
                if (!locFailLogged) AppLog.add("Sem localizacao (GPS/rede/ultima conhecida)")
                locFailLogged = true
                return@safe
            }
            locFailLogged = false
            val live = fix.source == "GPS" || fix.source == "NETWORK"
            val j = JSONObject().put("event_id", uuid()).put("lat", fix.lat).put("lon", fix.lon)
                .put("ts", if (live) fix.ts else System.currentTimeMillis()).put("source", fix.source)
            fix.acc?.let { j.put("accuracy", it.toDouble()) }
            Outbox.add("/api/v1/location", j.toString())
            AppLog.add("Localizacao ${fix.source} enfileirada")
        })
    }

    // ------------------------------------------------------------ eventos e alertas
    fun onEvent(type: String, meta: String = "sim") {
        work.execute(safe("evento") { processEvent(type, meta) })
    }

    private fun processEvent(type: String, meta: String) {
        val ts = System.currentTimeMillis()
        val j = JSONObject().put("event_id", uuid()).put("event_type", type).put("ts", ts).put("meta", meta)
        Outbox.add("/api/v1/events", j.toString())            // o servidor tambem reavalia as regras
        AppLog.add("Evento $type")
        val hits = engine.add(type, ts, cfg)
        if (hits.isNotEmpty()) {
            AppLog.add("Regra(s) disparada(s) no app: ${hits.joinToString()}")
            raiseAlert(hits, "Regra ${hits.joinToString()} (gatilho local)")
        }
    }

    fun manualAlert() {
        work.execute(safe("alerta") { raiseAlert(listOf("MANUAL"), "Alerta manual (teste foto+GPS)") })
    }

    private fun raiseAlert(rules: List<String>, detail: String) {
        val ts = System.currentTimeMillis()
        val fLoc = sensors.submit(Callable<Fix?> { LocationHelper.getFix(app, 3000) })
        val fPic = sensors.submit(Callable<ByteArray?> { CameraCapture.capture(app, 5000) })
        val pic = try { fPic.get(8, TimeUnit.SECONDS) } catch (e: Exception) { AppLog.add("Foto falhou: ${e.message}"); null }
        val fix = try { fLoc.get(6, TimeUnit.SECONDS) } catch (e: Exception) { null }

        val auto = rules.any { it in cfg.autoLock }
        if (auto) LockManager.lock(app, rules.joinToString())      // foto/GPS antes: a camera exige app em primeiro plano

        val b64 = pic?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
        if (pic == null) AppLog.add("Alerta sera enviado SEM foto")
        for (r in rules) {
            val j = JSONObject().put("event_id", uuid()).put("rule_id", r).put("ts", ts)
                .put("locked", auto).put("detail", detail)
            if (fix != null) {
                j.put("lat", fix.lat).put("lon", fix.lon).put("source", fix.source)
                fix.acc?.let { j.put("accuracy", it.toDouble()) }
            } else j.put("source", "NONE")
            if (b64 != null) j.put("photo_b64", b64)
            Outbox.add("/api/v1/alerts", j.toString())
        }
        AppLog.add("Alerta ${rules.joinToString()} enfileirado (foto=${pic != null}, gps=${fix?.source ?: "NONE"})")
    }

    // ------------------------------------------------------------ simulacao
    fun simulate(s: String) {
        val c = cfg
        when (s) {
            "R1" -> repeat(c.r1Max + 1) { onEvent("PIN_FAIL") }
            "R2" -> repeat(c.r2Max + 1) { onEvent("SENSITIVE_APP_OPEN") }
            "R3" -> { onEvent("PASSWORD_CHANGE"); onEvent("SENSITIVE_APP_OPEN") }
            "RESET" -> { engine.reset(); AppLog.add("Contadores locais zerados") }
            else -> onEvent(s)
        }
    }
}