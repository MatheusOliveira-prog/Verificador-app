[app]
title = Verificador de E-commerce
package.name = verificador
package.domain = org.meuverificador.app
source.dir = .
source.main_py = main.py
version = 1.0

# --- LINHA CORRIGIDA ---
requirements = python3,cython,kivy,requests,python-whois,beautifulsoup4,hashlib

orientation = portrait
android.permissions = INTERNET
android.api = 21
android.arch = arm64-v8a

[buildozer]
log_level = 2
warn_on_root = 1
