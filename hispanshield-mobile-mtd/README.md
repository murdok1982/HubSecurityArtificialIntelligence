# 📱 HispanShield Mobile - Mi Defensa Móvil (MTD)

Soy **Gustavo Lobato (MuRDoK)**. No podía dejar que los dispositivos móviles fueran el eslabón débil. Por eso he creado esta solución **Mobile Threat Defense (MTD)**, ahora integrada totalmente en mi ecosistema **HispanShield**.

## 🎯 Mi Visión Móvil

He diseñado esta aplicación en **Flutter** para que sea ligera pero implacable. Se alimenta directamente de mi Hub de Inteligencia de Amenazas y protege tu dispositivo contra:
- **Phishing por SMS**: Análisis en tiempo real de URLs maliciosas.
- **Apps Maliciosas**: Detección basada en firmas y comportamiento.
- **Llamadas Scam**: Identificación de números fraudulentos.
- **Anti-Tampering**: Si alguien intenta rootear o debuggear tu terminal, lo sabré.

## 🏗️ Cómo se conecta todo

Mi app móvil ya no está sola. Ahora envía toda su telemetría a mi **Backend Unificado** en FastAPI, donde correlaciono los eventos con los ataques que detecto en escritorio y servidores.

## 🚀 Entra en acción

### La App (Flutter)
```bash
cd mobile_app
flutter pub get
flutter run
```

### El Backend (Consolidado)
*Nota: El antiguo backend de esta carpeta ha sido jubilado. Ahora todo pasa por mi plataforma central `AntimalwareHispanPlataform`.*

## 📊 Cobertura MITRE
He mapeado personalmente las detecciones a las técnicas de **MITRE ATT&CK for Mobile**, para que sepas exactamente a qué nos enfrentamos.

---
**MuRDoK (Gustavo Lobato)**
*Protegiendo tu bolsillo desde tu smartphone.*
