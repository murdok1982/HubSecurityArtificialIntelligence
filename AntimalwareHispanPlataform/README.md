# 🛡️ HispanShield Platform - Mi Ecosistema de Ciberseguridad

Soy **Gustavo Lobato**, más conocido como **MuRDoK**, y este es mi proyecto estrella: una plataforma SaaS multi-tenant diseñada para el análisis avanzado de malware. He construido HispanShield para que sea el cerebro central de una red de defensa que abarca desde móviles hasta servidores críticos.

## 🚀 ¿Qué es HispanShield?

Es mi visión de una seguridad proactiva. Combina análisis estático, dinámico (sandbox) e inteligencia artificial para destripar cualquier binario malicioso y generar informes detallados. Ahora, lo he evolucionado para que sirva de **Backend Unificado** para mis agentes EDR y mis apps móviles.

### 🏗️ Mi Arquitectura

- **Cerebro (Backend)**: FastAPI con Python 3.11+. He optimizado cada endpoint para que sea rápido como un rayo.
- **Memoria (DB)**: PostgreSQL 15+ con aislamiento multi-tenant real (RLS). Tus datos son solo tuyos.
- **Músculo (Workers)**: Celery procesando tareas de triaje y análisis en segundo plano.
- **Inteligencia (CTI Hub)**: Mi propio motor de agregación de feeds (URLhaus, PhishTank, VT) integrado directamente.
- **Laboratorio (Sandboxes)**: Integración con Cuckoo/CAPE para ver cómo se comporta el malware en vivo.

## 📋 Lo que necesitas para empezar

- Docker y Docker Compose (Mi stack corre sobre contenedores para facilitar tu vida).
- Python 3.11+.
- Una instancia de Cuckoo CAPE si quieres el análisis dinámico completo.

## 🚀 Despegue rápido (Quick Start)

He simplificado todo para que puedas empezar en minutos:

```bash
# 1. Trae mi código a tu máquina
git clone <repo-url>
cd AntimalwareHispanPlataform

# 2. Prepara tu entorno virtual
python -m venv venv
.\venv\Scripts\activate  # Windows

# 3. Instala mis herramientas
pip install -r backend/requirements.txt

# 4. Enciende los motores (DB, Redis, Meilisearch)
docker-compose up -d

# 5. Prepara la base de datos
cd backend
alembic upgrade head
python scripts/init_db.py

# 6. ¡Lanza la API!
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## 📚 Mi Documentación

- **Mis APIs**: http://localhost:8000/docs (Swagger UI - Aquí puedes ver cómo hablo con mis agentes).
- **El Diseño**: He dejado los detalles de mi visión en `docs/diseno_arquitectonico_COMPLETO_FINAL.md`.

## 📁 Cómo he organizado el proyecto

- `/backend`: Toda mi lógica de negocio, APIs y modelos de datos.
- `/services/intel_service.py`: Mi nuevo Hub de Inteligencia de Amenazas.
- `/yara-rules`: Mi colección personal de firmas para cazar malware.

## 🔐 Mis variables de entorno

No olvides configurar tu `.env`. Necesitarás tu **VIRUSTOTAL_API_KEY** si quieres que HispanShield use todo su potencial de detección.

---
**Firmado,**
**MuRDoK (Gustavo Lobato)**
*Construyendo el futuro de la ciberseguridad, bit a bit.*
