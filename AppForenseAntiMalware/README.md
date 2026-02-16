# 🔍 Mi Herramienta Forense HispanShield

Soy **Gustavo Lobato (MuRDoK)**. Esta es la herramienta que uso cuando necesito bajar al barro y analizar una muestra de malware en profundidad. Originalmente era una herramienta "aislada", pero la he evolucionado para que sea una pieza clave de mi ecosistema **HispanShield**.

## 🚀 ¿Qué hace mi herramienta?

Diseñada para analistas que no se conforman con un "es malware". Realiza:
- **Ingesta rápida**: Arrastra y suelta para empezar.
- **Análisis Estático**: Extrae strings, cabeceras PE y entropía.
- **Motor YARA**: Usa mis propias reglas para identificar familias de malware.
- **Reportes PDF**: Genera un informe técnico listo para compartir.
- **☁️ Cloud Sync**: (Novedad) Ahora puedes sincronizar tus hallazgos directamente con mi plataforma SaaS centralizada.

## 🛠️ Cómo la he construido

- **GUI**: PySide6 (Qt) para una interfaz limpia y profesional.
- **Lógica**: Python puro, modular y extensible.
- **Base de Datos**: SQLite local para mantener la rapidez en el campo.

## 📁 Mi estructura

- `/app/gui`: Donde he diseñado toda la experiencia visual.
- `/app/core`: El motor de análisis y el nuevo servicio `cloud_sync.py`.
- `/edr`: Mi nuevo agente de detección en tiempo real que comparte el ADN de esta herramienta.

## 🚀 Ponla en marcha

```bash
# 1. Instala lo que necesito
pip install -r app/requirements.txt

# 2. Lánzala
python app/main.py
```

---
**MuRDoK (Gustavo Lobato)**
*Analizando el peligro, un byte a la vez.*
