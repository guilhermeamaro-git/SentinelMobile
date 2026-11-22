package com.sentinel.mobile

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent

class AdminReceiver : DeviceAdminReceiver()

/** Janela deslizante local. Espelha ingest_event() do servidor (mesmas regras R1/R2/R3 e cooldown). */
class RuleEngine {
    private class Ev(val type: String, val ts: Long)

    private val evs = ArrayList<Ev>()
    private val lastFire = HashMap<String, Long>()

    @Synchronized
    fun reset() { evs.clear(); lastFire.clear() }

    @Synchronized
    fun add(type: String, ts: Long, c: Cfg): List<String> {
        evs.add(Ev(type, ts))
        evs.removeAll { ts - it.ts > 3_600_000 }
        val hits = ArrayList<String>()

        fun windowStart(rule: String, winSec: Int): Long? {
            val base = lastFire[rule] ?: 0L
            val d = ts - base
            if (base != 0L && d >= 0 && d < c.cooldown * 1000L) return null      // em cooldown
            return maxOf(ts - winSec * 1000L, base)                                // contadores zerados no ultimo disparo
        }
        fun count(t: String, lo: Long) = evs.count { it.type == t && it.ts > lo && it.ts <= ts }

        if (type == "PIN_FAIL") {
            windowStart("R1", c.r1Win)?.let { if (count("PIN_FAIL", it) > c.r1Max) hits.add("R1") }
        }
        if (type == "SENSITIVE_APP_OPEN") {
            windowStart("R2", c.r2Win)?.let { if (count("SENSITIVE_APP_OPEN", it) > c.r2Max) hits.add("R2") }
            windowStart("R3", c.r3Win)?.let { if (count("PASSWORD_CHANGE", it) >= 1) hits.add("R3") }
        }
        hits.forEach { lastFire[it] = ts }
        return hits
    }
}

object LockManager {
    fun component(ctx: Context) = ComponentName(ctx, AdminReceiver::class.java)

    private fun dpm(ctx: Context) = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    fun isAdmin(ctx: Context): Boolean = dpm(ctx).isAdminActive(component(ctx))

    /** Bloqueio em duas camadas: tela do app (fallback) + lockNow() se o Device Admin estiver ativo. */
    fun lock(ctx: Context, reason: String) {
        Prefs.locked = true
        AppLog.add("BLOQUEIO acionado ($reason)")
        try {
            ctx.startActivity(Intent(ctx, LockActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP))
        } catch (e: Exception) { AppLog.add("Tela de bloqueio nao abriu: ${e.message}") }
        if (isAdmin(ctx)) {
            try { dpm(ctx).lockNow(); AppLog.add("lockNow() executado") }
            catch (e: SecurityException) { AppLog.add("lockNow() negado: ${e.message}") }
        } else {
            AppLog.add("Device Admin inativo: so a tela de bloqueio do app foi usada")
        }
    }

    fun unlock(ctx: Context) {
        Prefs.locked = false
        AppLog.add("Bloqueio removido")
    }
}