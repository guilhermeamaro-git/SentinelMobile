package com.sentinel.mobile

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageFormat
import android.graphics.Matrix
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.media.ImageReader
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.view.Surface
import java.io.ByteArrayOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

object LocationHelper {

    /** Ordem: fix ao vivo (GPS/NETWORK) -> ultima posicao do sistema -> ultima salva no app -> null. */
    fun getFix(ctx: Context, timeoutMs: Long): Fix? {
        val perm = ctx.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
                ctx.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (perm && !Prefs.forceNoGps) {
            val live = acquireLive(ctx, timeoutMs)
            if (live != null) { Prefs.lastFix = live; return live }
            val sys = systemLastKnown(ctx)
            if (sys != null) return sys
        }
        return Prefs.lastFix?.copy(source = "LAST_KNOWN")
    }

    @SuppressLint("MissingPermission")
    private fun acquireLive(ctx: Context, timeoutMs: Long): Fix? {
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val ref = AtomicReference<Fix?>(null)
        val latch = CountDownLatch(1)
        val listener = object : LocationListener {
            override fun onLocationChanged(l: Location) {
                val src = if (l.provider == LocationManager.GPS_PROVIDER) "GPS" else "NETWORK"
                val acc = if (l.hasAccuracy()) l.accuracy else null
                if (ref.compareAndSet(null, Fix(l.latitude, l.longitude, acc, System.currentTimeMillis(), src))) latch.countDown()
            }
            @Deprecated("old API") override fun onStatusChanged(p: String?, s: Int, e: Bundle?) {}
            override fun onProviderEnabled(p: String) {}
            override fun onProviderDisabled(p: String) {}
        }
        try {
            val providers = listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)
                .filter { try { lm.isProviderEnabled(it) } catch (e: Exception) { false } }
            if (providers.isEmpty()) return null
            providers.forEach { lm.requestLocationUpdates(it, 0L, 0f, listener, Looper.getMainLooper()) }
            latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: SecurityException) {
            AppLog.add("Sem permissao de localizacao")
        } finally {
            try { lm.removeUpdates(listener) } catch (e: Exception) {}
        }
        return ref.get()
    }

    @SuppressLint("MissingPermission")
    private fun systemLastKnown(ctx: Context): Fix? {
        val lm = ctx.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        return try {
            listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)
                .mapNotNull { try { lm.getLastKnownLocation(it) } catch (e: Exception) { null } }
                .maxByOrNull { it.time }
                ?.let { Fix(it.latitude, it.longitude, if (it.hasAccuracy()) it.accuracy else null, it.time, "LAST_KNOWN") }
        } catch (e: SecurityException) { null }
    }
}

object CameraCapture {

    /** Foto silenciosa da camera frontal (sem preview na tela). Retorna JPEG reduzido (~640 px) ou null. */
    @Suppress("DEPRECATION")
    @SuppressLint("MissingPermission")
    fun capture(ctx: Context, timeoutMs: Long = 5000): ByteArray? {
        if (ctx.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            AppLog.add("Camera: sem permissao"); return null
        }
        val mgr = ctx.getSystemService(Context.CAMERA_SERVICE) as CameraManager
        val id = try {
            mgr.cameraIdList.firstOrNull {
                mgr.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_FRONT
            }
        } catch (e: Exception) { null }
        if (id == null) { AppLog.add("Camera frontal nao encontrada"); return null }

        val ch = mgr.getCameraCharacteristics(id)
        val rot = ch.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 270
        val sizes = ch.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)?.getOutputSizes(ImageFormat.JPEG) ?: return null
        val size = sizes.filter { it.width <= 1280 }.maxByOrNull { it.width * it.height }
            ?: sizes.minByOrNull { it.width * it.height } ?: return null

        val thread = HandlerThread("sentinel-cam").apply { start() }
        val h = Handler(thread.looper)
        val reader = ImageReader.newInstance(size.width, size.height, ImageFormat.JPEG, 2)
        val tex = SurfaceTexture(10).apply { setDefaultBufferSize(640, 480) }
        val dummy = Surface(tex)                      // "preview" invisivel: permite o auto-exposure convergir
        val out = AtomicReference<ByteArray?>(null)
        val done = CountDownLatch(1)
        var cam: CameraDevice? = null

        reader.setOnImageAvailableListener({ r ->
            val img = r.acquireLatestImage()
            if (img != null) {
                try {
                    val b = img.planes[0].buffer
                    val bytes = ByteArray(b.remaining()); b.get(bytes); out.set(bytes)
                } finally { img.close() }
                done.countDown()
            }
        }, h)

        try {
            mgr.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(c: CameraDevice) {
                    cam = c
                    try {
                        c.createCaptureSession(listOf(dummy, reader.surface), object : CameraCaptureSession.StateCallback() {
                            override fun onConfigured(s: CameraCaptureSession) {
                                try {
                                    val pv = c.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply { addTarget(dummy) }
                                    s.setRepeatingRequest(pv.build(), null, h)
                                    h.postDelayed({
                                        try {
                                            val st = c.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE).apply {
                                                addTarget(reader.surface)
                                                set(CaptureRequest.JPEG_QUALITY, 85.toByte())
                                            }
                                            s.capture(st.build(), null, h)
                                        } catch (e: Exception) { AppLog.add("Camera captura: ${e.message}"); done.countDown() }
                                    }, 800)           // 0,8 s de "aquecimento" para exposicao
                                } catch (e: Exception) { AppLog.add("Camera sessao: ${e.message}"); done.countDown() }
                            }
                            override fun onConfigureFailed(s: CameraCaptureSession) { done.countDown() }
                        }, h)
                    } catch (e: Exception) { AppLog.add("Camera: ${e.message}"); done.countDown() }
                }
                override fun onDisconnected(c: CameraDevice) { c.close(); done.countDown() }
                override fun onError(c: CameraDevice, error: Int) { c.close(); AppLog.add("Camera erro $error"); done.countDown() }
            }, h)
            done.await(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: Exception) {
            AppLog.add("Camera: ${e.message}")
        } finally {
            try { cam?.close() } catch (e: Exception) {}
            reader.close(); dummy.release(); tex.release(); thread.quitSafely()
        }
        val raw = out.get() ?: return null
        return shrink(raw, rot)
    }

    private fun shrink(raw: ByteArray, rot: Int): ByteArray? {
        val bmp = BitmapFactory.decodeByteArray(raw, 0, raw.size) ?: return null
        val m = Matrix().apply { postRotate(rot.toFloat()) }
        val scale = 640f / maxOf(bmp.width, bmp.height)
        if (scale < 1f) m.postScale(scale, scale)
        val b2 = Bitmap.createBitmap(bmp, 0, 0, bmp.width, bmp.height, m, true)
        val bos = ByteArrayOutputStream()
        b2.compress(Bitmap.CompressFormat.JPEG, 70, bos)
        return bos.toByteArray()
    }
}