package com.sentinel.mobile

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

class LockActivity : Activity() {
    private val ui = Handler(Looper.getMainLooper())
    private lateinit var info: TextView
    private lateinit var pin: EditText
    private lateinit var go: Button
    private val watch = object : Runnable {
        override fun run() {
            if (!Prefs.locked) { finish(); return }   // UNLOCK remoto chega via polling
            updateState()
            ui.postDelayed(this, 1000)
        }
    }

    private fun updateState() {
        val wait = Pin.blockedForMs()
        go.isEnabled = Pin.isSet() && wait == 0L
        info.text = when {
            !Pin.isSet() -> "PIN do app nao definido.\nO proprietario pode liberar pelo painel."
            wait > 0 -> "Muitas tentativas erradas.\nTente de novo em ${(wait + 999) / 1000} s."
            else -> "Bloqueio antirroubo ativo.\nO proprietario pode liberar pelo painel."
        }
    }

    private fun tryUnlock() {
        when (Pin.attempt(pin.text.toString())) {
            is Pin.Result.Ok -> { LockManager.unlock(this); finish() }
            is Pin.Result.Wrong -> {
                // Erro na propria tela de bloqueio conta como tentativa de forca bruta (regra R1).
                Sentinel.onEvent("PIN_FAIL", "tela de bloqueio")
                Toast.makeText(this, "PIN incorreto", Toast.LENGTH_SHORT).show()
            }
            is Pin.Result.Blocked, is Pin.Result.NotSet -> Unit
        }
        pin.setText("")
        updateState()
    }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        pin = EditText(this).apply {
            hint = "PIN de emergencia"; gravity = Gravity.CENTER
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            setTextColor(Color.WHITE); setHintTextColor(Color.argb(160, 255, 255, 255))
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER
            setBackgroundColor(Color.parseColor("#B91C1C")); setPadding(60, 60, 60, 60)
            addView(TextView(context).apply {
                text = "DISPOSITIVO BLOQUEADO"; textSize = 26f; setTextColor(Color.WHITE); gravity = Gravity.CENTER
            })
            info = TextView(context).apply {
                setTextColor(Color.WHITE); gravity = Gravity.CENTER; setPadding(0, 30, 0, 30)
            }
            addView(info)
            addView(pin)
            go = Button(context).apply {
                text = "Desbloquear"
                setOnClickListener { tryUnlock() }
            }
            addView(go)
        }
        setContentView(root)
        updateState()
    }

    @Deprecated("Bloqueia o botao voltar")
    override fun onBackPressed() { /* ignorado enquanto bloqueado */ }

    override fun onResume() { super.onResume(); ui.post(watch) }
    override fun onPause() { super.onPause(); ui.removeCallbacks(watch) }

    /**
     * Home e Recentes nao podem ser bloqueados por um app comum, entao a tela vermelha sozinha e
     * facil de contornar. Se ela sair de cena enquanto o aparelho esta bloqueado, travamos a tela do
     * proprio Android (lockNow), que exige o PIN/biometria do aparelho.
     */
    override fun onStop() {
        super.onStop()
        if (Prefs.locked && !isChangingConfigurations) LockManager.lockScreen(this)
    }
}