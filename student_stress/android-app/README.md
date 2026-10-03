# Clarity Android app

This WebView app connects to the FastAPI server running on your computer. The server address is entered once in the app and saved on the phone, so the APK does not need to be rebuilt when your Wi-Fi address changes.

## Start the local server

In the project directory on the computer, run:

```powershell
.venv\Scripts\Activate.ps1
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Find the computer's Wi-Fi IPv4 address with `ipconfig` (for example, `192.168.1.25`). In the Android app, enter `http://192.168.1.25:8000`. Connect the phone and computer to the same Wi-Fi network. Allow Python through Windows Firewall on private networks if Windows asks.

## Build the APK

Open this `android-app` folder in Android Studio and build **Build > Build Bundle(s) / APK(s) > Build APK(s)**. The APK will be in `app/build/outputs/apk/debug/app-debug.apk`.

The Android project requires JDK 17 or newer, Android SDK Platform 34, and Android Gradle Plugin 8.6.1. The debug APK is suitable for local installation and testing.
