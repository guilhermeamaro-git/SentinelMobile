package com.sentinel.mobile

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import java.util.Locale

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var logView: TextView
    private val ui = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() { refresh(); ui.postDelayed(this, 1000) }
    }

    private fun dp(i: Int) = (i * resources.displayMetrics.density).toInt()

    private fun head(t: String) = TextView(this).apply {
        text = t; textSize = 15f; setTypeface(null, Typeface.BOLD); setPadding(0, dp(16), 0, dp(4))
    }
    private fun input(h: String, v: String) = EditText(this).apply {
        hint = h; setText(v); setSingleLine(); textSize = 13f
    }
    private fun btn(t: String, f: () -> Unit) = Button(this).apply {
        text = t; isAllCaps = false; textSize = 12f; setOnClickListener { f() }
    }
    private fun row(vararg v: View) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        v.forEach { addView(it, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)) }
    }
    private fun toggle(t: String, on: Boolean, f: (Boolean) -> Unit) = Switch(this).apply {
        text = t; isChecked = on; setOnCheckedChangeListener { _, b -> f(b) }
    }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(14), dp(14), dp(14))
        }
        setContentView(ScrollView(this).apply { addView(root) })

        root.addView(TextView(this).apply { text = "SentinelMobile"; textSize = 22f; setTypeface(null, Typeface.BOLD) })
        status = TextView(this).apply { typeface = Typeface.MONOSPACE; textSize = 11f; setPadding(0, dp(8), 0, 0) }
        root.addView(status)

        // --- conexao
        root.addView(head("Conexao"))
        val url = input("URL (https://IP:8443)", Prefs.baseUrl)
        val did = input("Device ID (nome do aparelho no painel)", Prefs.deviceId)
        val code = input("Codigo de pareamento (gerado no painel)", "")
        root.addView(url); root.addView(did); root.addView(code)
        root.addView(row(
            btn("Salvar") {
                Prefs.baseUrl = url.text.toString()
                // Depois de pareado, o nome no servidor vem do token: renomear exige parear de novo.
                if (Prefs.token.isNotEmpty() && did.text.toString().trim() != Prefs.deviceId) {
                    did.setText(Prefs.deviceId)
                    Toast.makeText(this, "Para trocar o Device ID, gere um codigo e pareie de novo", Toast.LENGTH_LONG).show()
                } else {
                    Prefs.deviceId = did.text.toString()
                    Toast.makeText(this, "Salvo", Toast.LENGTH_SHORT).show()
                }
                Sentinel.refreshNow()
            },
            btn("Parear") {
                Prefs.baseUrl = url.text.toString(); Prefs.deviceId = did.text.toString()
                if (code.text.isBlank()) Toast.makeText(this, "Gere um codigo no painel", Toast.LENGTH_SHORT).show()
                else { Sentinel.pair(code.text.toString()); code.setText("") }
            },
            btn("Testar conexao") { Sentinel.testConnection() }
        ))

        // --- permissoes e bloqueio
        root.addView(head("Permissoes e bloqueio"))
        root.addView(row(
            btn("Permissoes") { askPermissions() },
            btn("Ativar Device Admin") { requestAdmin() }
        ))
        root.addView(row(
            btn("Bloquear agora") { Sentinel.sendLocationNow(); LockManager.lock(this, "botao local") },
            btn("Desbloquear") { LockManager.unlock(this) }
        ))

        // --- simulacao
        root.addView(head("Simulacao (eventos reais do pipeline)"))
        root.addView(row(btn("R1: PIN") { Sentinel.simulate("R1") }, btn("R2: apps") { Sentinel.simulate("R2") }, btn("R3: senha") { Sentinel.simulate("R3") }))
        root.addView(row(btn("+ PIN falho") { Sentinel.simulate("PIN_FAIL") }, btn("+ App sensivel") { Sentinel.simulate("SENSITIVE_APP_OPEN") }))
        root.addView(row(btn("+ Troca senha") { Sentinel.simulate("PASSWORD_CHANGE") }, btn("Zerar contadores") { Sentinel.simulate("RESET") }))
        root.addView(row(btn("Alerta manual (foto+GPS)") { Sentinel.manualAlert() }, btn("Enviar localizacao") { Sentinel.sendLocationNow() }))
        root.addView(toggle("Simular queda de rede (testa fila/retry)", Prefs.simOffline) {
            Prefs.simOffline = it; AppLog.add(if (it) "Rede SIMULADA offline" else "Rede restaurada")
        })
        root.addView(toggle("Simular sem GPS (testa fallback)", Prefs.forceNoGps) {
            Prefs.forceNoGps = it; AppLog.add(if (it) "GPS desligado (simulado)" else "GPS normal")
        })

        // --- PIN interno (o PIN nunca e exibido; erros viram PIN_FAIL e alimentam a R1)
        root.addView(head("PIN do app (sai da tela de bloqueio; erros disparam a R1)"))
        val pin = input("digite o PIN", "").apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        }
        root.addView(pin)
        root.addView(row(
            btn("Testar PIN") {
                if (checkPin(pin.text.toString())) toast("PIN correto")
                pin.setText("")
            },
            btn("Trocar PIN (digite o atual)") {
                if (checkPin(pin.text.toString())) askNewPin(firstTime = false)
                pin.setText("")
            }
        ))

        // --- log
        root.addView(head("Log"))
        logView = TextView(this).apply { typeface = Typeface.MONOSPACE; textSize = 10f; setTextIsSelectable(true) }
        root.addView(logView)

        askPermissions()
        if (!Pin.isSet()) askNewPin(firstTime = true)   // nao existe PIN padrao
        // Device Admin e obrigatorio: sem ele o bloqueio e so a tela do app, contornavel pelo botao Home.
        if (!LockManager.isAdmin(this)) requestAdmin()
    }

    private fun requestAdmin() {
        startActivity(Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
            .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, LockManager.component(this))
            .putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "Obrigatorio: permite travar a tela do aparelho (lockNow) quando um ataque e detectado " +
                "ou quando o painel manda bloquear. Sem isso o bloqueio pode ser contornado."))
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    /** Confere o PIN com o mesmo limite de tentativas da tela de bloqueio (senao viraria um atalho para adivinhar). */
    private fun checkPin(p: String): Boolean = when (val r = Pin.attempt(p)) {
        is Pin.Result.Ok -> true
        is Pin.Result.Wrong -> { toast("PIN incorreto"); Sentinel.onEvent("PIN_FAIL", "PIN interno"); false }
        is Pin.Result.Blocked -> { toast("Muitas tentativas. Aguarde ${(r.remainingMs + 999) / 1000} s"); false }
        is Pin.Result.NotSet -> { askNewPin(firstTime = true); false }
    }

    private fun askNewPin(firstTime: Boolean) {
        val field = EditText(this).apply {
            hint = "4 a 8 digitos"
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        }
        val dlg = AlertDialog.Builder(this)
            .setTitle(if (firstTime) "Defina o PIN do app" else "Novo PIN do app")
            .setMessage("Usado para sair da tela de bloqueio. Nao existe PIN padrao.")
            .setView(field)
            .setCancelable(!firstTime)
            .setPositiveButton("Salvar") { _, _ ->
                val p = field.text.toString()
                if (Pin.isValidFormat(p)) { Pin.set(p); AppLog.add("PIN do app definido"); toast("PIN salvo") }
                else { toast("O PIN deve ter de 4 a 8 digitos"); askNewPin(firstTime) }
            }
        if (!firstTime) dlg.setNegativeButton("Cancelar", null)
        dlg.show()
    }

    private fun askPermissions() {
        val need = arrayOf(Manifest.permission.CAMERA, Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
            .filter { checkSelfPermission(it) != android.content.pm.PackageManager.PERMISSION_GRANTED }
        if (need.isNotEmpty()) requestPermissions(need.toTypedArray(), 1)
    }

    override fun onResume() {
        super.onResume()
        if (Prefs.locked) {
            startActivity(Intent(this, LockActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP))
        }
        ui.post(tick)
    }

    override fun onPause() { super.onPause(); ui.removeCallbacks(tick) }

    private fun refresh() {
        val fix = Prefs.lastFix
        val c = Sentinel.cfg
        status.text = buildString {
            if (!LockManager.isAdmin(this@MainActivity))
                appendLine("!! DEVICE ADMIN INATIVO: o bloqueio NAO protege. Toque em 'Ativar Device Admin'.")
            appendLine("Rede    : " + (if (Sentinel.online) "ONLINE" else "OFFLINE") + " - " + Sentinel.netInfo)
            appendLine("PIN app : " + (if (Pin.isSet()) "definido" else "NAO definido"))
            appendLine("Pareado : " + (if (Prefs.token.isNotEmpty()) "sim (${Prefs.deviceId})" else "NAO - gere um codigo no painel"))
            appendLine("Fila    : ${Outbox.size()} pendente(s) | ${Outbox.lastStatus}")
            appendLine("Bloqueio: " + (if (Prefs.locked) "BLOQUEADO" else "livre") +
                    " | DeviceAdmin: " + (if (LockManager.isAdmin(this@MainActivity)) "ativo" else "INATIVO"))
            appendLine("Posicao : " + (fix?.let { String.format(Locale.US, "%.5f, %.5f (%s)", it.lat, it.lon, it.source) } ?: "sem fix"))
            append("Regras  : R1>${c.r1Max}/${c.r1Win}s R2>${c.r2Max}/${c.r2Win}s R3<${c.r3Win}s auto=${c.autoLock}")
        }
        logView.text = AppLog.text()
    }
}