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
    private val watch = object : Runnable {
        override fun run() { if (!Prefs.locked) finish() else ui.postDelayed(this, 1000) }   // UNLOCK remoto chega via polling
    }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val pin = EditText(this).apply {
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
            addView(TextView(context).apply {
                text = "Bloqueio antirroubo ativo.\nO proprietario pode liberar pelo painel."
                setTextColor(Color.WHITE); gravity = Gravity.CENTER; setPadding(0, 30, 0, 30)
            })
            addView(pin)
            addView(Button(context).apply {
                text = "Desbloquear"
                setOnClickListener {
                    if (pin.text.toString() == Prefs.unlockPin) { LockManager.unlock(context); finish() }
                    else { Toast.makeText(context, "PIN incorreto", Toast.LENGTH_SHORT).show(); pin.setText("") }
                }
            })
        }
        setContentView(root)
    }

    @Deprecated("Bloqueia o botao voltar")
    override fun onBackPressed() { /* ignorado enquanto bloqueado */ }

    override fun onResume() { super.onResume(); ui.post(watch) }
    override fun onPause() { super.onPause(); ui.removeCallbacks(watch) }
}