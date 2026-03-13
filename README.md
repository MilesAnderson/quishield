# quishield

# Mobile use of quishield:

Steps on your android mobile device:
    Enabling the android debug bridge.
        1. Go to settings > about phone, and tap on the build number 7 times to enable 
        developer options.
        2. Go to settings > system developer options and enable USB debugging.
        3. Using a cable that allows for information passing, plug your device in to the
        computer and accept the prompt.
        4. type adb devices in to the terminal. The android device should show with the
        description "Device".

Installing and running quishield
    1. Still with the device plugged in, type .\gradlew installDebug in to the root directory.
    2. The apk should be installed, and the application should automatically appear on the
    homescreen of your android device. If not, ensure android studio is set up with the kotlin
    compiler, and the java toolkit.
    3. Open the application on the android device. You should now be able to view the
    application interface, and scan and upload images with QR codes.






1. Ensure you have androide studio installed on a computer, this will be much easier than using another IDE like VScode.
2. 

Code references:
Android developers guide: Utalized for Quishield photo picker and working with uris.
    https://developer.android.com/training/data-storage/shared/photo-picker

QR code and bar code detector API information and CameraX:
    https://developer.android.com/media/camera/camerax/analyze