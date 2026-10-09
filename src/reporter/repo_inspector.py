"""Inspector determinista de seguridad del propio repositorio.

Recorre el árbol de archivos de forma reproducible y aplica reglas basadas en
patrones observables. Cada coincidencia genera una :class:`EvidenceItem` con
archivo, línea y fragmento (con los secretos redactados) y contribuye a un
:class:`Finding`. No se ejecuta código del repositorio ni se realizan llamadas
de red: el resultado debe ser idéntico entre ejecuciones para el mismo árbol.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

from .models import EvidenceItem, Finding, InspectionResult, Severity

INSPECTOR_VERSION = "0.1.0"

# Aspectos alineados con el workflow de referencia
# ``daily-action-setup-security-audit`` (8 aspectos + seguridad de workflows).
ASPECTS: list[str] = [
    "secret-handling",
    "command-injection",
    "network-requests",
    "supply-chain",
    "file-permissions",
    "github-token-scope",
    "sandbox-escape",
    "output-injection",
    "workflow-security",
]

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".ipynb_checkpoints",
    "dist",
    "build",
    # Salida del propio Reporter: evita que un reporte commiteado se reaudite a
    # sí mismo y genere hallazgos autoreferenciales.
    "reports",
    # Fixtures de prueba con patrones inseguros deliberados.
    "tests",
}

# Marcadores de valores de relleno que no son credenciales reales.
_PLACEHOLDER_RE = re.compile(
    r"(?i)(\[redacted\]|redacted|changeme|change[_-]?me|placeholder|example|"
    r"your[_-]|token[_-]here|secret[_-]here|<[^>\s]+>)"
)


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(value))

# El motor de reglas contiene, como metadatos, fragmentos que coinciden con sus
# propios patrones (p. ej. "chmod 777" en una descripción o la URL de ejemplo de
# una regla). Se excluye para no reportar el propio texto de las reglas.
SELF_EXCLUDED = "src/reporter"

MAX_FILE_BYTES = 1_000_000
MAX_SNIPPET = 300


@dataclass(frozen=True)
class Rule:
    """Regla determinista aplicada línea a línea."""

    aspect: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    remediation: str
    pattern: re.Pattern[str]
    applies_to: Optional[Callable[[str], bool]] = None
    confidence: str = "high"
    redact: bool = False


def _is_workflow(path: str) -> bool:
    return path.startswith(".github/workflows/") and (
        path.endswith(".yml") or path.endswith(".yaml")
    )


def _is_dockerfile(path: str) -> bool:
    name = Path(path).name
    return name == "Dockerfile" or name.startswith("Dockerfile.")


def _is_shell(path: str) -> bool:
    return path.endswith((".sh", ".bash", ".zsh"))


def _is_code(path: str) -> bool:
    return path.endswith((".py", ".js", ".ts", ".cjs", ".mjs"))


_DOCKER_FROM = re.compile(
    r"^\s*FROM\s+(?![^\n]*@sha256:)([A-Za-z0-9._/\-]+)(?::[A-Za-z0-9._\-]+)?"
    r"(?:\s+AS\s+\S+)?\s*$",
    re.IGNORECASE,
)


RULES: list[Rule] = [
    # --- secret-handling ---------------------------------------------------
    Rule(
        "secret-handling",
        "secret-quoted",
        Severity.HIGH,
        "Posible secreto embebido en el código",
        "Se detectó una asignación con aspecto de credencial. Los secretos no "
        "deben vivir en el repositorio: quedan expuestos en el historial.",
        "Mover el valor a variables de entorno/secretos y rotarlo.",
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*[\"']([^\"']{8,})[\"']"
        ),
        redact=True,
    ),
    Rule(
        "secret-handling",
        "secret-env-file",
        Severity.HIGH,
        "Valor sensible en archivo de entorno versionado",
        "Un archivo de entorno contiene una credencial en texto plano.",
        "Excluir el archivo con .gitignore y rotar la credencial.",
        re.compile(r"(?i)^\s*(api[_-]?key|secret|token|password|passwd)\s*=\s*(\S{8,})"),
        applies_to=lambda p: Path(p).name == ".env",
        redact=True,
    ),
    Rule(
        "secret-handling",
        "secret-aws-key",
        Severity.CRITICAL,
        "Posible clave AWS",
        "El texto coincide con el prefijo de un Access Key ID de AWS.",
        "Revocar la clave y usar un gestor de secretos.",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        redact=True,
    ),
    Rule(
        "secret-handling",
        "secret-private-key",
        Severity.CRITICAL,
        "Clave privada en el repositorio",
        "Se encontró el encabezado de una clave privada.",
        "Eliminar la clave del repositorio, rotarla y purgar el historial.",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ),
    # --- command-injection -------------------------------------------------
    Rule(
        "command-injection",
        "ci-shell-true",
        Severity.MEDIUM,
        "Ejecución de subproceso con shell=True",
        "Pasar datos no confiables a un shell habilita inyección de comandos.",
        "Usar una lista de argumentos y evitar shell=True.",
        re.compile(r"subprocess\.\w+\s*\([^)\n]*shell\s*=\s*True"),
        applies_to=_is_code,
    ),
    Rule(
        "command-injection",
        "ci-os-system",
        Severity.HIGH,
        "Uso de os.system",
        "os.system ejecuta una cadena a través del shell del sistema.",
        "Preferir subprocess.run con una lista de argumentos.",
        re.compile(r"\bos\.system\s*\("),
        applies_to=_is_code,
    ),
    Rule(
        "command-injection",
        "ci-dynamic-eval",
        Severity.MEDIUM,
        "Evaluación dinámica de código (eval/exec)",
        "eval y exec ejecutan datos como código si reciben entrada externa.",
        "Evitar eval/exec o restringir estrictamente su entrada.",
        re.compile(r"(?<![\w.])(eval|exec)\s*\("),
        applies_to=_is_code,
    ),
    # --- network-requests --------------------------------------------------
    Rule(
        "network-requests",
        "net-verify-false",
        Severity.HIGH,
        "Verificación TLS deshabilitada",
        "verify=False acepta certificados no válidos y habilita MITM.",
        "Eliminar verify=False y confiar en el almacén de CA del sistema.",
        re.compile(r"verify\s*=\s*False"),
        applies_to=_is_code,
    ),
    Rule(
        "network-requests",
        "net-plain-http",
        Severity.INFO,
        "URL sin cifrado (http://)",
        "Se detectó una URL http:// que viaja sin cifrado.",
        "Usar https:// salvo que el destino sea estrictamente local.",
        re.compile(r"http://[^\s\"')`]+"),
        applies_to=_is_code,
    ),
    # --- supply-chain ------------------------------------------------------
    Rule(
        "supply-chain",
        "sc-unpinned-action",
        Severity.HIGH,
        "GitHub Action sin fijar a un SHA",
        "Las referencias mutables (v4, main) pueden cambiar sin aviso: riesgo de "
        "compromiso de la cadena de suministro.",
        "Fijar cada action a un SHA de commit de 40 caracteres.",
        re.compile(
            r"uses:\s*[^\s#@]+@(?![0-9a-fA-F]{7,40}\b)"
            r"(?:v?\d[\w.\-]*|main|master|latest|HEAD)\b"
        ),
        applies_to=_is_workflow,
    ),
    Rule(
        "supply-chain",
        "sc-docker-unpinned",
        Severity.MEDIUM,
        "Imagen base sin fijar por digest",
        "Una etiqueta de imagen puede reescribirse y alterar la build.",
        "Fijar la imagen base por digest (@sha256:...).",
        _DOCKER_FROM,
        applies_to=_is_dockerfile,
    ),
    # --- file-permissions --------------------------------------------------
    Rule(
        "file-permissions",
        "fp-world-writable",
        Severity.HIGH,
        "Permisos world-writable (chmod 777)",
        "chmod 777 hace que cualquier usuario pueda modificar el archivo.",
        "Aplicar el mínimo privilegio (p. ej. chmod 600/700).",
        re.compile(r"chmod\s+(?:-[\w]+\s+)*777\b"),
    ),
    Rule(
        "file-permissions",
        "fp-world-readable",
        Severity.MEDIUM,
        "Permisos world-readable (chmod 666)",
        "chmod 666 expone el contenido a cualquier usuario del sistema.",
        "Restringir los permisos a lo estrictamente necesario (600).",
        re.compile(r"chmod\s+(?:-[\w]+\s+)*666\b"),
    ),
    # --- github-token-scope ------------------------------------------------
    Rule(
        "github-token-scope",
        "tok-write-all",
        Severity.HIGH,
        "Permisos de workflow write-all",
        "write-all otorga al GITHUB_TOKEN permisos de escritura en todos los "
        "ámbitos, mucho más de lo necesario.",
        "Declarar permisos mínimos explícitos (contents: read)",
        re.compile(r"permissions:\s*write-all"),
        applies_to=_is_workflow,
    ),
    Rule(
        "github-token-scope",
        "tok-persist-credentials",
        Severity.MEDIUM,
        "persist-credentials activado en checkout",
        "Las credenciales de Git quedan guardadas en el workspace y pueden ser "
        "exfiltradas por pasos posteriores.",
        "Definir persist-credentials: false en actions/checkout.",
        re.compile(r"persist-credentials:\s*true"),
        applies_to=_is_workflow,
    ),
    # --- sandbox-escape ----------------------------------------------------
    Rule(
        "sandbox-escape",
        "sb-privileged-op",
        Severity.LOW,
        "Operación que interactúa con el kernel/aislamiento",
        "Comandos como nsenter, unshare, chroot, iptables o sysctl pueden "
        "romper el aislamiento del entorno de ejecución.",
        "Confirmar que la operación es imprescindible y está restringida.",
        re.compile(r"\b(nsenter|unshare|chroot|iptables|sysctl)\b"),
        applies_to=_is_shell,
    ),
    # --- output-injection --------------------------------------------------
    Rule(
        "output-injection",
        "out-script-injection",
        Severity.HIGH,
        "Inyección de script en workflow vía contexto",
        "Interpolar github.event/inputs directamente en un run: permite a un "
        "atacante inyectar comandos a través de títulos, ramas, etc.",
        "Pasar los valores por variables de entorno y citarlos.",
        re.compile(
            r"\$\{\{\s*(?:github\.event|github\.head_ref|github\.head_commit|inputs)\b"
        ),
        applies_to=_is_workflow,
    ),
    Rule(
        "output-injection",
        "out-github-output",
        Severity.MEDIUM,
        "Escritura no saneada en GITHUB_OUTPUT/GITHUB_ENV",
        "Escribir datos controlados por el usuario en archivos de entorno/output "
        "puede inyectar líneas nuevas y variables.",
        "Validar y escapar los valores antes de escribirlos.",
        re.compile(r"(?:GITHUB_OUTPUT|GITHUB_ENV)\b[^\n]*\$\{\{"),
        applies_to=_is_workflow,
    ),
    # --- workflow-security -------------------------------------------------
    Rule(
        "workflow-security",
        "ws-pull-request-target",
        Severity.HIGH,
        "Trigger pull_request_target",
        "pull_request_target se ejecuta con secretos y token de escritura sobre "
        "código de forks: vector clásico de escalada.",
        "Evitar pull_request_target o no ejecutar código del PR sin checkout seguro.",
        re.compile(r"\bpull_request_target\b"),
        applies_to=_is_workflow,
    ),
    Rule(
        "workflow-security",
        "ws-untrusted-checkout-ref",
        Severity.MEDIUM,
        "Checkout de una ref no confiable",
        "Hacer checkout de github.event.* puede ejecutar código de un PR/fork.",
        "Fijar la ref a un valor confiable o validar su origen.",
        re.compile(r"ref:\s*\$\{\{\s*github\.event"),
        applies_to=_is_workflow,
    ),
]


def _iter_source_files(repo_root: Path) -> list[Path]:
    """Lista archivos de forma determinista, excluyendo directorios pesados."""
    files: list[Path] = []
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root).as_posix()
        if rel == SELF_EXCLUDED or rel.startswith(SELF_EXCLUDED + "/"):
            continue
        rel_parts = path.relative_to(repo_root).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts):
            continue
        if any(
            rel_parts[i] == "data" and rel_parts[i + 1] == "raw"
            for i in range(len(rel_parts) - 1)
        ):
            continue
        files.append(path)
    return files


def _read_text(path: Path, max_bytes: int) -> Optional[str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) > max_bytes:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def _hash_id(*parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest[:12]


def _make_evidence(
    rule: Rule, rel: str, line_no: int, line: str, match: re.Match[str]
) -> EvidenceItem:
    snippet = line.strip()
    if rule.redact:
        secret = match.group(match.lastindex) if match.lastindex else match.group(0)
        if secret:
            snippet = snippet.replace(secret, "[REDACTED]")
    snippet = snippet[:MAX_SNIPPET]
    return EvidenceItem(
        evidence_id=_hash_id(rule.aspect, rule.rule_id, rel, str(line_no), snippet),
        aspect=rule.aspect,
        file=rel,
        start_line=line_no,
        end_line=line_no,
        snippet=snippet,
        snippet_sha256=hashlib.sha256(snippet.encode("utf-8")).hexdigest(),
        rule=rule.rule_id,
    )


def _add_finding(
    findings: dict[str, Finding],
    rule: Rule,
    evidence_id: str,
    location_count: int = 1,
) -> None:
    finding_id = f"{rule.aspect}:{rule.rule_id}"
    finding = findings.get(finding_id)
    if finding is None:
        finding = Finding(
            finding_id=finding_id,
            aspect=rule.aspect,
            severity=rule.severity,
            title=rule.title,
            description=rule.description,
            confidence=rule.confidence,
            remediation=rule.remediation,
        )
        findings[finding_id] = finding
    if evidence_id not in finding.evidence_ids:
        finding.evidence_ids.append(evidence_id)


def collect_evidence(
    repo_root: Path,
    aspects: Optional[Iterable[str]] = None,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> InspectionResult:
    """Inspecciona el repositorio y devuelve evidencia determinista.

    Args:
        repo_root: raíz del repositorio a auditar.
        aspects: subconjunto de :data:`ASPECTS` a evaluar (None = todos).
        max_file_bytes: límite de tamaño para leer un archivo.

    Each finding references the evidence that supports it, so no claim is
    emitted without an observable file/line.
    """
    repo_root = Path(repo_root).resolve()
    selected = list(aspects) if aspects is not None else list(ASPECTS)
    selected_set = set(selected)

    evidence: list[EvidenceItem] = []
    findings: dict[str, Finding] = {}
    files_scanned = 0

    for path in _iter_source_files(repo_root):
        rel = path.relative_to(repo_root).as_posix()
        text = _read_text(path, max_file_bytes)
        if text is None:
            continue
        files_scanned += 1
        lines = text.splitlines()

        for line_no, line in enumerate(lines, start=1):
            for rule in RULES:
                if rule.aspect not in selected_set:
                    continue
                if rule.applies_to and not rule.applies_to(rel):
                    continue
                for match in rule.pattern.finditer(line):
                    if rule.redact:
                        secret = (
                            match.group(match.lastindex)
                            if match.lastindex
                            else match.group(0)
                        )
                        if secret and _is_placeholder(secret):
                            continue
                    item = _make_evidence(rule, rel, line_no, line, match)
                    evidence.append(item)
                    _add_finding(findings, rule, item.evidence_id)

        # Comprobaciones a nivel de archivo.
        if Path(rel).name == ".env" and "secret-handling" in selected_set:
            env_rule = Rule(
                "secret-handling",
                "secret-committed-env",
                Severity.HIGH,
                "Archivo .env versionado",
                "El archivo .env no debería estar en el control de versiones.",
                "Añadir .env a .gitignore y usar .env.example.",
                re.compile(r"$^"),
            )
            item = EvidenceItem(
                evidence_id=_hash_id("secret-handling", "secret-committed-env", rel, "1"),
                aspect="secret-handling",
                file=rel,
                start_line=1,
                end_line=1,
                snippet=".env (archivo versionado)",
                snippet_sha256=hashlib.sha256(b".env").hexdigest(),
                rule="secret-committed-env",
            )
            evidence.append(item)
            _add_finding(findings, env_rule, item.evidence_id)

        if (
            _is_workflow(rel)
            and "workflow-security" in selected_set
            and not re.search(r"(?m)^\s*permissions\s*:", text)
        ):
            missing_rule = Rule(
                "workflow-security",
                "ws-missing-permissions",
                Severity.INFO,
                "Workflow sin bloque permissions",
                "Sin 'permissions:' el GITHUB_TOKEN hereda el valor por defecto, "
                "que puede ser más amplio de lo necesario.",
                "Declarar permisos mínimos de forma explícita.",
                re.compile(r"$^"),
            )
            item = EvidenceItem(
                evidence_id=_hash_id("workflow-security", "ws-missing-permissions", rel, "1"),
                aspect="workflow-security",
                file=rel,
                start_line=1,
                end_line=1,
                snippet="permissions: <ausente>",
                snippet_sha256=hashlib.sha256(b"permissions-missing").hexdigest(),
                rule="ws-missing-permissions",
            )
            evidence.append(item)
            _add_finding(findings, missing_rule, item.evidence_id)

    evidence.sort(key=lambda e: (e.file, e.start_line, e.rule, e.evidence_id))
    ordered_findings = sorted(
        findings.values(),
        key=lambda f: (f.severity.rank, f.aspect, f.finding_id),
    )

    return InspectionResult(
        repo_root=str(repo_root),
        inspector_version=INSPECTOR_VERSION,
        generated_at=datetime.now(timezone.utc),
        files_scanned=files_scanned,
        aspects=selected,
        evidence=evidence,
        findings=ordered_findings,
    )
