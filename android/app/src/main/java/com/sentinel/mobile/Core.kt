package com.sentinel.mobile

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.UUID

class SentinelApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Sentinel.init(this)
    }
}

data class Fix(val lat: Double, val lon: Double, val acc: Float?, val ts: Long, val source: String)

/** Parametros da heuristica (espelham o servidor; sao baixados de /api/v1/config). */
data class Cfg(
    val r1Max: Int = 3, val r1Win: Int = 120,
    val r2Max: Int = 3, val r2Win: Int = 120,
    val r3Win: Int = 90, val cooldown: Int = 30,
    val autoLock: Set<String> = setOf("R1", "R3")
)

object Prefs {
    private lateinit var sp: SharedPreferences
    fun init(ctx: Context) {
        sp = ctx.getSharedPreferences("sentinel", Context.MODE_PRIVATE)
        // Limpa o token compartilhado da versao antiga (agora cada aparelho tem o seu).
        if (sp.contains("token")) sp.edit().remove("token").apply()
    }

    var baseUrl: String
        get() = sp.getString("baseUrl", "https://127.0.0.1:8443")!!
        set(v) = sp.edit().putString("baseUrl", v.trim().trimEnd('/')).apply()

    /** Token exclusivo deste aparelho, recebido no pareamento (POST /api/v1/register). */
    var token: String
        get() = sp.getString("deviceToken", "")!!
        set(v) = sp.edit().putString("deviceToken", v.trim()).apply()

    var deviceId: String
        get() {
            var d = sp.getString("deviceId", null)
            if (d == null) {
                d = "phone-" + UUID.randomUUID().toString().take(6)
                sp.edit().putString("deviceId", d).apply()
            }
            return d
        }
        set(v) {
            val clean = v.trim().replace(Regex("[^A-Za-z0-9_.-]"), "_").take(64)
            if (clean.isNotEmpty()) sp.edit().putString("deviceId", clean).apply()
        }

    var locked: Boolean
        get() = sp.getBoolean("locked", false)
        set(v) = sp.edit().putBoolean("locked", v).apply()

    var unlockPin: String
        get() = sp.getString("unlockPin", "1234")!!
        set(v) = sp.edit().putString("unlockPin", v).apply()

    var simOffline: Boolean
        get() = sp.getBoolean("simOffline", false)
        set(v) = sp.edit().putBoolean("simOffline", v).apply()

    var forceNoGps: Boolean
        get() = sp.getBoolean("forceNoGps", false)
        set(v) = sp.edit().putBoolean("forceNoGps", v).apply()

    var lastFix: Fix?
        get() {
            val s = sp.getString("lastFix", null) ?: return null
            return try {
                val p = s.split("|")
                Fix(p[0].toDouble(), p[1].toDouble(), p[2].toFloatOrNull(), p[3].toLong(), p[4])
            } catch (e: Exception) { null }
        }
        set(v) {
            if (v != null) sp.edit()
                .putString("lastFix", "${v.lat}|${v.lon}|${v.acc ?: ""}|${v.ts}|${v.source}").apply()
        }
}

object AppLog {
    private val lines = ArrayDeque<String>()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    @Synchronized
    fun add(msg: String) {
        lines.addFirst(fmt.format(Date()) + "  " + msg)
        while (lines.size > 60) lines.removeLast()
        android.util.Log.i("Sentinel", msg)
    }

    @Synchronized
    fun text(): String = lines.joinToString("\n")
}