# `data/` — Estado Persistente y Seguridad Interna

Este directorio representa el **estado persistente, auditable y sensible** de AegisNode.

No contiene lógica, código ejecutable ni claves criptográficas. Su única función es **registrar el estado de seguridad del sistema de forma determinística y verificable**.

---

## Principio de diseño

> *"Si el código define cómo funciona el sistema, `data/` demuestra que funciona y que no ha sido manipulado."*

`data/` existe para garantizar:

* Protección contra **replay attacks**
* Detección de **eventos atrasados o reordenados**
* **Auditoría forense** post‑incidente
* Evidencia de **integridad histórica**

---

## Estructura del directorio

```
data/
│
├── seen_hashes.json
├── last_timestamps.json
├── accepted_events.json
├── rejected_events.json
├── audit_state.json
└── README.md
```

---

##  Descripción de archivos

###  `seen_hashes.json`

**Rol:** Anti‑replay persistente

Almacena los hashes SHA‑256 de todos los eventos que ya han sido procesados y aceptados.

* Si un evento entrante tiene un hash ya presente → **se rechaza inmediatamente**
* Protege contra:

  * reenvío de eventos
  * duplicación maliciosa
  * manipulación silenciosa

Este archivo es **crítico para la seguridad del sistema**.

---

###  `last_timestamps.json`

**Rol:** Validación temporal por nodo

Guarda el último timestamp aceptado por cada nodo emisor.

* Si un evento llega con un timestamp menor al registrado → rechazo
* Protege contra:

  * eventos atrasados
  * reordenamiento de tráfico
  * replay diferido

Garantiza una **línea temporal estrictamente creciente**.

---

###  `accepted_events.json`

**Rol:** Trazabilidad mínima

Registro compacto de eventos aceptados, sin almacenar el contenido completo.

Se utiliza para:

* auditoría
* verificación posterior
* análisis de comportamiento

Funciona como un **ledger ligero**, no como un log detallado.

---

###  `rejected_events.json`

**Rol:** Análisis forense

Registra eventos rechazados junto con la razón del rechazo.

Permite:

* detectar patrones de ataque
* depuración avanzada
* evidencia de controles activos

Este archivo demuestra que el sistema **no falla en silencio**.

---

###  `audit_state.json`

**Rol:** Núcleo del sistema de auditoría

Mantiene el estado del **Secure Audit Log**:

* último hash válido
* longitud de la cadena
* última verificación

Permite detectar:

* eliminación de entradas
* modificación retroactiva
* ruptura de continuidad

Es la base del comando `audit verify`.

---

##  Reglas de seguridad

* `data/` **no debe versionarse** (excepto este README)
* Si un archivo falta:

  * se recrea vacío
  * se registra como evento de auditoría
* Modificar manualmente cualquier archivo **rompe la confianza del sistema**
* Todo acceso debe ser:

  * determinístico
  * explícito
  * auditable

---

##  Valor técnico

La existencia y correcta gestión de `data/` demuestra conocimiento en:

* diseño de sistemas seguros
* separación estado / lógica
* detección de ataques pasivos
* auditoría criptográfica
* arquitectura defensiva

Este enfoque es comparable a sistemas utilizados en:

* SIEM
* Zero‑Trust Gateways
* Infraestructura crítica

---

##  Advertencia

Este directorio contiene **estado sensible**.

Eliminar o modificar su contenido puede:

* invalidar auditorías
* romper garantías de seguridad
* ocultar intentos de ataque

---

*AegisNode no confía en la memoria. Confía en la evidencia.*

