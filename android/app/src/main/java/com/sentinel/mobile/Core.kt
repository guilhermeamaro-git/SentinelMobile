package com.sentinel.mobile

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale
import java.util.UUID
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

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
        // Limpa dados da versao antiga: token compartilhado e PIN em texto puro.
        if (sp.contains("token") || sp.contains("unlockPin")) sp.edit().remove("token").remove("unlockPin").apply()
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

    // PIN do app: so o hash (PBKDF2) e o salt ficam salvos, nunca o PIN em si.
    var pinHash: String
        get() = sp.getString("pinHash", "")!!
        set(v) = sp.edit().putString("pinHash", v).apply()

    var pinSalt: String
        get() = sp.getString("pinSalt", "")!!
        set(v) = sp.edit().putString("pinSalt", v).apply()

    var pinFails: Int
        get() = sp.getInt("pinFails", 0)
        set(v) = sp.edit().putInt("pinFails", v).apply()

    var pinBlockedUntil: Long
        get() = sp.getLong("pinBlockedUntil", 0L)
        set(v) = sp.edit().putLong("pinBlockedUntil", v).apply()

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

/**
 * PIN do app (tela de bloqueio e teste de R1).
 * - Nao existe PIN padrao: o usuario define no primeiro uso.
 * - Guardamos PBKDF2(PIN, salt) em vez do PIN.
 * - Depois de 5 erros seguidos, novas tentativas ficam bloqueadas por 30 s, dobrando a cada erro
 *   (ate 15 min). A contagem fica salva, entao fechar o app nao zera. Sao 5 (e nao 3) para a
 *   regra R1 (padrao: mais de 3 falhas) disparar, com foto, antes do bloqueio por tempo.
 * Cada erro tambem vira um evento PIN_FAIL (quem chama e que envia), alimentando a regra R1.
 */
object Pin {
    sealed class Result {
        object Ok : Result()
        object Wrong : Result()
        class Blocked(val remainingMs: Long) : Result()
        object NotSet : Result()
    }

    private const val ITERATIONS = 20_000
    private const val FREE_ATTEMPTS = 5

    fun isSet() = Prefs.pinHash.isNotEmpty()

    fun isValidFormat(p: String) = p.length in 4..8 && p.all { it in '0'..'9' }

    fun set(p: String) {
        require(isValidFormat(p)) { "PIN deve ter de 4 a 8 digitos" }
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        Prefs.pinSalt = Base64.encodeToString(salt, Base64.NO_WRAP)
        Prefs.pinHash = Base64.encodeToString(derive(p, salt), Base64.NO_WRAP)
        Prefs.pinFails = 0
        Prefs.pinBlockedUntil = 0L
    }

    fun blockedForMs(): Long = maxOf(0L, Prefs.pinBlockedUntil - System.currentTimeMillis())

    @Synchronized
    fun attempt(p: String): Result {
        if (!isSet()) return Result.NotSet
        val wait = blockedForMs()
        if (wait > 0) return Result.Blocked(wait)
        val salt = Base64.decode(Prefs.pinSalt, Base64.NO_WRAP)
        val expected = Base64.decode(Prefs.pinHash, Base64.NO_WRAP)
        if (MessageDigest.isEqual(derive(p, salt), expected)) {   // comparacao em tempo constante
            Prefs.pinFails = 0
            Prefs.pinBlockedUntil = 0L
            return Result.Ok
        }
        val fails = Prefs.pinFails + 1
        Prefs.pinFails = fails
        if (fails >= FREE_ATTEMPTS) {
            val delay = minOf(15 * 60_000L, 30_000L shl minOf(fails - FREE_ATTEMPTS, 5))
            Prefs.pinBlockedUntil = System.currentTimeMillis() + delay
        }
        return Result.Wrong
    }

    private fun derive(p: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(p.toCharArray(), salt, ITERATIONS, 256)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}
