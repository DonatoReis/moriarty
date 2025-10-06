"""Template Scanner - Sistema estilo Nuclei para detecção de vulnerabilidades."""
import asyncio
import itertools
import json
import random
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlsplit, urlunsplit

import httpx
import structlog
import yaml
from rich.console import Console
from rich.progress import Progress

if TYPE_CHECKING:  # pragma: no cover - apenas para type hints
    from moriarty.modules.stealth_mode import StealthMode

logger = structlog.get_logger(__name__)
console = Console()


@dataclass
class TemplateFinding:
    """Resultado de template scan."""
    template_id: str
    name: str
    severity: str
    description: str
    matched_at: str
    extracted_data: Dict[str, Any]


@dataclass
class Template:
    """Template de vulnerabilidade."""
    id: str
    info: Dict[str, Any]
    requests: List[Dict[str, Any]]
    matchers: List[Dict[str, Any]]
    extractors: Optional[List[Dict[str, Any]]] = None
    matchers_condition: str = "or"
    tags: Set[str] = field(default_factory=set)


class TemplateScanner:
    """
    Scanner baseado em templates YAML (estilo Nuclei).
    
    Suporta:
    - HTTP requests
    - Matchers (status, word, regex, dsl)
    - Extractors (regex, kval, json)
    - Variables
    - Payloads
    - Raw requests
    """
    
    FUZZ_PAYLOADS: Dict[str, List[str]] = {
        "sqli": ["' OR '1'='1", "' UNION SELECT NULL--", "1; DROP TABLE users"],
        "xss": ["<script>alert(1)</script>", '" onmouseover="alert(1)"', "'><img src=x onerror=alert(1)>"],
        "lfi": ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"],
        "cmd": [";id", "| whoami", "$(whoami)", "&& dir"],
        "path": ["..;/", "..%2f"],
    }

    def __init__(
        self,
        target: str,
        templates_path: Optional[str] = None,
        severity_filter: Optional[List[str]] = None,
        threads: int = 20,
        timeout: float = 10.0,
        tag_filter: Optional[List[str]] = None,
        stealth: Optional["StealthMode"] = None,
    ):
        self.target = target
        self.templates_path = templates_path or self._get_default_templates_path()
        self.severity_filter = severity_filter
        self.threads = threads
        self.timeout = timeout
        self.tag_filter = {tag.lower() for tag in tag_filter} if tag_filter else None
        self.stealth = stealth
        self.findings: List[TemplateFinding] = []
        self._finding_cache: Set[Tuple[str, str]] = set()
        self.template_ids: Set[str] = set()

        normalized_target = self._ensure_scheme(target)
        parsed = urlparse(normalized_target)
        self.scheme = parsed.scheme or "https"
        self.host = parsed.netloc or parsed.path
        self.base_url = f"{self.scheme}://{self.host}"

        # Mantém alvo original para logging
        self.target = normalized_target

    def _stealth_headers(self) -> Dict[str, str]:
        if not self.stealth:
            return {}
        headers = self.stealth.get_random_headers()
        headers.setdefault("User-Agent", headers.get("User-Agent", "Mozilla/5.0 (Moriarty Recon)"))
        headers.setdefault("Accept", "*/*")
        return headers

    async def _stealth_delay(self) -> None:
        if not self.stealth:
            return
        config = getattr(self.stealth, "config", None)
        if not config or not getattr(config, "timing_randomization", False):
            return
        await asyncio.sleep(random.uniform(0.05, 0.2) * max(1, self.stealth.level))
    
    def _get_default_templates_path(self) -> str:
        """Retorna path padrão de templates."""
        return str(Path(__file__).parent.parent / "assets" / "templates")

    def _ensure_scheme(self, target: str) -> str:
        """Garante que o alvo possua esquema HTTP/S."""
        if target.startswith("http://") or target.startswith("https://"):
            return target
        return f"https://{target}"
    
    async def scan(self) -> List[TemplateFinding]:
        """Executa scan usando templates."""
        logger.info("template.scan.start", target=self.target, templates_path=self.templates_path)
        
        # Carrega templates
        templates = self._load_templates()

        # Filtra por severidade
        if self.severity_filter:
            templates = [t for t in templates if t.info.get("severity") in self.severity_filter]

        if self.tag_filter:
            filtered = [t for t in templates if t.tags and (t.tags & self.tag_filter)]
            if filtered:
                templates = filtered
            else:
                logger.debug("template.scan.tag_filter_empty", tags=sorted(self.tag_filter))

        console.print(f"[cyan]📝 Loaded {len(templates)} templates[/cyan]\n")

        # Executa templates
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            semaphore = asyncio.Semaphore(self.threads)
            
            tasks = [
                self._execute_template(client, semaphore, template)
                for template in templates
            ]
            
            with Progress() as progress:
                task_id = progress.add_task("[cyan]Scanning...", total=len(tasks))
                
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task_id)
        
        logger.info("template.scan.complete", findings=len(self.findings))
        return self.findings
    
    def _load_templates(self) -> List[Template]:
        """Carrega templates de diretório."""
        templates = []
        templates_dir = Path(self.templates_path)

        if not templates_dir.exists():
            logger.warning("template.load.not_found", path=self.templates_path)
            # Cria templates de exemplo
            self._create_example_templates()
            return self._load_templates()

        self.template_ids.clear()

        # Busca arquivos .yaml recursivamente
        for yaml_file in templates_dir.rglob("*.yaml"):
            try:
                with open(yaml_file, 'r') as f:
                    data = yaml.safe_load(f) or {}

                if not isinstance(data, dict):
                    logger.warning("template.load.invalid", file=str(yaml_file))
                    continue

                if not self._validate_template(data, yaml_file):
                    continue

                template_id = data.get("id", yaml_file.stem)
                if template_id in self.template_ids:
                    logger.warning("template.load.duplicate", template=template_id, file=str(yaml_file))
                    continue

                matchers_condition = (
                    data.get("matchers-condition")
                    or data.get("matchers_condition")
                    or "or"
                ).lower()

                requests = data.get("requests", data.get("http", [])) or []
                if not isinstance(requests, list):
                    requests = [requests]

                normalized_requests = [
                    self._normalize_request(request)
                    for request in requests
                    if isinstance(request, dict)
                ]

                info = data.get("info", {})
                raw_tags = info.get("tags", [])
                if isinstance(raw_tags, str):
                    tags = {raw_tags.lower()}
                else:
                    tags = {str(tag).lower() for tag in raw_tags}

                template = Template(
                    id=template_id,
                    info=info,
                    requests=normalized_requests,
                    matchers=data.get("matchers", []),
                    extractors=data.get("extractors", []),
                    matchers_condition=matchers_condition,
                    tags=tags,
                )

                templates.append(template)
                self.template_ids.add(template_id)
                
            except Exception as e:
                logger.warning("template.load.error", file=str(yaml_file), error=str(e))
        
        logger.info("template.load.complete", count=len(templates))
        return templates

    def _normalize_request(self, request_def: Dict[str, Any]) -> Dict[str, Any]:
        """Normaliza campos comuns de requests."""
        normalized = dict(request_def)

        path = normalized.get("path")
        if isinstance(path, str):
            normalized["path"] = [path]

        raw = normalized.get("raw")
        if isinstance(raw, str):
            normalized["raw"] = [raw]

        matchers_condition = (
            normalized.get("matchers-condition")
            or normalized.get("matchers_condition")
        )
        if matchers_condition:
            normalized["matchers_condition"] = matchers_condition

        return normalized

    def _validate_template(self, data: Dict[str, Any], file_path: Path) -> bool:
        """Valida estrutura mínima de um template."""
        errors = []

        template_id = data.get("id")
        if not template_id:
            errors.append("missing id")

        info = data.get("info", {})
        severity = info.get("severity")
        allowed_severities = {"critical", "high", "medium", "low", "info"}
        if severity and severity.lower() not in allowed_severities:
            errors.append(f"invalid severity '{severity}'")

        requests = data.get("requests", data.get("http", [])) or []
        if not isinstance(requests, list) or not requests:
            errors.append("missing requests")
        else:
            for index, request in enumerate(requests):
                if not isinstance(request, dict):
                    errors.append(f"request[{index}] is not a mapping")
                    continue
                has_path = bool(request.get("path"))
                has_raw = bool(request.get("raw"))
                if not has_path and not has_raw:
                    errors.append(f"request[{index}] missing path/raw")

        if errors:
            logger.warning(
                "template.validation.failed",
                file=str(file_path),
                errors=errors,
            )
            return False

        return True
    
    async def _execute_template(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        template: Template,
    ):
        """Executa um template."""
        async with semaphore:
            try:
                for request_def in template.requests:
                    matchers = request_def.get("matchers") or template.matchers
                    extractors = request_def.get("extractors") or template.extractors or []
                    matchers_condition = (
                        request_def.get("matchers_condition")
                        or request_def.get("matchers-condition")
                        or template.matchers_condition
                        or "or"
                    ).lower()
                    stop_on_match = bool(
                        request_def.get("stop-at-first-match")
                        or request_def.get("stop_at_first_match")
                    )

                    payload_maps = self._build_payload_maps(request_def)
                    raw_blocks = request_def.get("raw") or []
                    match_found = False

                    if raw_blocks:
                        for payload_map in payload_maps:
                            for raw in raw_blocks:
                                raw_payload = self._apply_payload(raw, payload_map)
                                method, url, headers, body = self._parse_raw_request(raw_payload)

                                request_kwargs = {}
                                if body is not None:
                                    request_kwargs["content"] = body.encode() if isinstance(body, str) else body

                                merged_headers = {**self._stealth_headers(), **(headers or {})}
                                await self._stealth_delay()
                                response = await client.request(
                                    method,
                                    url,
                                    headers=merged_headers,
                                    **request_kwargs,
                                )

                                match_found = self._process_response(
                                    template,
                                    url,
                                    response,
                                    matchers,
                                    matchers_condition,
                                    extractors,
                                ) or match_found

                                if match_found and stop_on_match:
                                    return

                        # Se requests RAW foram processados, pula para próximo request
                        continue

                    paths = request_def.get("path") or ["/"]
                    if isinstance(paths, str):
                        paths = [paths]

                    method = request_def.get("method", "GET")
                    headers_template = request_def.get("headers", {})
                    body_template = request_def.get("body")

                    for payload_map in payload_maps:
                        for path in paths:
                            final_path = self._apply_payload(path, payload_map)
                            url = self._build_url(final_path)

                            headers = self._prepare_headers(headers_template, payload_map)
                            headers = {**self._stealth_headers(), **headers}
                            body = self._prepare_body(body_template, payload_map)
                            request_kwargs = self._build_request_kwargs(body, request_def)

                            await self._stealth_delay()
                            response = await client.request(
                                method,
                                url,
                                headers=headers,
                                **request_kwargs,
                            )

                            match_found = self._process_response(
                                template,
                                url,
                                response,
                                matchers,
                                matchers_condition,
                                extractors,
                            ) or match_found

                            if match_found and stop_on_match:
                                break

                            fuzz_spec = request_def.get("fuzz")
                            if fuzz_spec:
                                match_found = await self._run_query_fuzz(
                                    client,
                                    template,
                                    url,
                                    headers,
                                    method,
                                    request_kwargs,
                                    fuzz_spec,
                                    matchers,
                                    matchers_condition,
                                    extractors,
                                    int(request_def.get("fuzz_max", 30)),
                                    stop_on_match,
                                    match_found,
                                )
                                if match_found and stop_on_match:
                                    break

                            if match_found and stop_on_match:
                                break

                        if match_found and stop_on_match:
                            break

                    if match_found and stop_on_match:
                        break

            except Exception as e:
                logger.debug("template.execute.error", template=template.id, error=str(e))
    
    def _build_url(self, path: str) -> str:
        """Constrói URL completa."""
        path = self._resolve_placeholders(path)

        if path.startswith("http://") or path.startswith("https://"):
            return path

        if not path.startswith("/"):
            path = f"/{path}"

        return f"{self.base_url}{path}"
    
    def _check_matchers(
        self,
        matchers: List[Dict[str, Any]],
        response: httpx.Response,
        matchers_condition: str = "or",
    ) -> bool:
        """Verifica se matchers são satisfeitos."""
        if not matchers:
            return False

        results: List[bool] = []

        for matcher in matchers:
            matcher_type = matcher.get("type", "word").lower()
            condition = matcher.get("condition", "or").lower()
            negative = bool(matcher.get("negative"))
            result = False

            if matcher_type == "status":
                status_codes = matcher.get("status") or matcher.get("codes") or []
                result = response.status_code in status_codes

            elif matcher_type == "word":
                words = matcher.get("words", [])
                part = matcher.get("part", "body")
                content = self._get_response_part(response, part)
                matches = [word.lower() in content.lower() for word in words]
                result = all(matches) if condition == "and" else any(matches)

            elif matcher_type == "regex":
                regexes = matcher.get("regex", [])
                part = matcher.get("part", "body")
                content = self._get_response_part(response, part)
                matches = [bool(re.search(regex, content, re.IGNORECASE)) for regex in regexes]
                result = all(matches) if condition == "and" else any(matches)

            elif matcher_type == "dsl":
                expressions = matcher.get("dsl", [])
                result = self._evaluate_dsl(expressions, response)

            if negative:
                result = not result

            results.append(result)

        if not results:
            return False

        if matchers_condition == "and":
            return all(results)
        return any(results)

    def _process_response(
        self,
        template: Template,
        url: str,
        response: httpx.Response,
        matchers: List[Dict[str, Any]],
        matchers_condition: str,
        extractors: List[Dict[str, Any]],
    ) -> bool:
        """Processa response, aplicando matchers e registrando findings."""
        if not matchers:
            return False

        if not self._check_matchers(matchers, response, matchers_condition):
            return False

        extracted = self._extract_data(extractors, response) if extractors else {}
        cache_key = (template.id, url)
        if cache_key in self._finding_cache:
            return True

        self._finding_cache.add(cache_key)

        finding = TemplateFinding(
            template_id=template.id,
            name=template.info.get("name", template.id),
            severity=template.info.get("severity", "info"),
            description=template.info.get("description", ""),
            matched_at=url,
            extracted_data=extracted,
        )

        self.findings.append(finding)

        logger.info(
            "template.match",
            template=template.id,
            severity=finding.severity,
            url=url,
        )

        colors = {
            "critical": "red",
            "high": "yellow",
            "medium": "blue",
            "low": "green",
            "info": "dim",
        }
        color = colors.get(finding.severity, "white")
        console.print(f"[{color}]✓ {finding.name} [{finding.severity.upper()}][/{color}]")

        return True

    def _build_payload_maps(self, request_def: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Gera combinações de payloads para placeholders."""
        payloads = request_def.get("payloads") or {}
        auto_fuzz = request_def.get("auto_fuzz")
        if isinstance(auto_fuzz, dict):
            for placeholder, entries in auto_fuzz.items():
                values = self._resolve_fuzz_values(entries if isinstance(entries, list) else [entries])
                if values:
                    payloads.setdefault(placeholder, values)
        elif isinstance(auto_fuzz, list):
            for idx, category in enumerate(auto_fuzz, start=1):
                values = self._resolve_fuzz_values([category])
                if values:
                    payloads.setdefault(f"fuzz_{idx}", values)
        if not payloads:
            return [{}]

        keys = list(payloads.keys())
        value_lists = [payloads[key] for key in keys]
        combinations = []
        max_combos = int(request_def.get("max_payload_combinations", 256))

        for index, combo in enumerate(itertools.product(*value_lists)):
            if index >= max_combos:
                logger.debug(
                    "template.payloads.limited",
                    template=request_def.get("id"),
                    max=max_combos,
                )
                break
            combinations.append(dict(zip(keys, combo)))

        return combinations or [{}]

    def _apply_payload(self, value: Any, payload_map: Dict[str, Any]) -> Any:
        """Aplica placeholders e payloads em strings/listas/dicts."""
        if value is None:
            return None

        if isinstance(value, str):
            result = value
            for key, payload in payload_map.items():
                result = result.replace(f"{{{{{key}}}}}", str(payload))
            return self._resolve_placeholders(result)

        if isinstance(value, list):
            return [self._apply_payload(item, payload_map) for item in value]

        if isinstance(value, dict):
            return {k: self._apply_payload(v, payload_map) for k, v in value.items()}

        return value

    def _resolve_fuzz_values(self, entries: List[str]) -> List[str]:
        values: List[str] = []
        for entry in entries:
            if entry in self.FUZZ_PAYLOADS:
                values.extend(self.FUZZ_PAYLOADS[entry])
            else:
                values.append(entry)
        seen: Set[str] = set()
        unique: List[str] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                unique.append(value)
        return unique

    def _normalize_fuzz_spec(self, fuzz_spec: Any) -> Dict[str, List[str]]:
        if not isinstance(fuzz_spec, dict):
            return {}
        normalized: Dict[str, List[str]] = {}
        for param, entries in fuzz_spec.items():
            if isinstance(entries, str):
                entries = [entries]
            if not isinstance(entries, list):
                continue
            values = self._resolve_fuzz_values(entries)
            if values:
                normalized[param] = values
        return normalized

    async def _run_query_fuzz(
        self,
        client: httpx.AsyncClient,
        template: Template,
        url: str,
        headers: Dict[str, Any],
        method: str,
        request_kwargs: Dict[str, Any],
        fuzz_spec: Any,
        matchers: List[Dict[str, Any]],
        matchers_condition: str,
        extractors: List[Dict[str, Any]],
        max_mutations: int,
        stop_on_match: bool,
        current_match: bool,
    ) -> bool:
        method_upper = method.upper()
        if method_upper not in {"GET", "HEAD", "DELETE"}:
            return current_match

        fuzz_map = self._normalize_fuzz_spec(fuzz_spec)
        if not fuzz_map:
            return current_match

        parsed = urlsplit(url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)
        for key in fuzz_map:
            base_params.setdefault(key, [""])

        keys = list(fuzz_map.keys())
        values_lists = [fuzz_map[key] for key in keys]

        mutations = 0
        for combo in itertools.product(*values_lists):
            if max_mutations > 0 and mutations >= max_mutations:
                logger.debug("template.fuzz.limit", template=template.id, limit=max_mutations)
                break

            params = {key: values[:] for key, values in base_params.items()}
            for key, payload in zip(keys, combo):
                params[key] = [payload]

            new_query = urlencode(params, doseq=True)
            fuzz_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))

            request_headers = {**self._stealth_headers(), **(headers or {})}
            await self._stealth_delay()
            response = await client.request(
                method_upper,
                fuzz_url,
                headers=request_headers,
                **request_kwargs,
            )

            current_match = self._process_response(
                template,
                fuzz_url,
                response,
                matchers,
                matchers_condition,
                extractors,
            ) or current_match

            mutations += 1
            if current_match and stop_on_match:
                break

        return current_match

    def _resolve_placeholders(self, value: str) -> str:
        """Resolve placeholders padrão (BaseURL, Hostname, Target)."""
        replacements = {
            "{{BaseURL}}": self.base_url,
            "{{base_url}}": self.base_url,
            "{{RootURL}}": self.base_url,
            "{{root_url}}": self.base_url,
            "{{Hostname}}": self.host,
            "{{hostname}}": self.host,
            "{{Target}}": self.host,
            "{{target}}": self.host,
        }

        result = value
        for placeholder, replacement in replacements.items():
            result = result.replace(placeholder, replacement)

        return result

    def _prepare_headers(
        self,
        headers_template: Dict[str, Any],
        payload_map: Dict[str, Any],
    ) -> Dict[str, str]:
        """Prepara headers aplicando payloads e defaults."""
        headers = {
            key: self._apply_payload(str(value), payload_map)
            for key, value in (headers_template or {}).items()
        }

        headers.setdefault("Host", self.host)
        return headers

    def _prepare_body(self, body_template: Any, payload_map: Dict[str, Any]) -> Any:
        """Prepara body aplicando payloads."""
        if body_template is None:
            return None
        return self._apply_payload(body_template, payload_map)

    def _build_request_kwargs(self, body: Any, request_def: Dict[str, Any]) -> Dict[str, Any]:
        """Monta kwargs para httpx.request."""
        kwargs: Dict[str, Any] = {}

        if body is None:
            return kwargs

        if isinstance(body, dict):
            if request_def.get("json", True):
                kwargs["json"] = body
            else:
                kwargs["data"] = body
        else:
            kwargs["content"] = body.encode() if isinstance(body, str) else body

        return kwargs

    def _parse_raw_request(self, raw_request: str) -> Tuple[str, str, Dict[str, str], Optional[str]]:
        """Converte request RAW estilo Nuclei em componentes httpx."""
        lines = raw_request.splitlines()
        if not lines:
            raise ValueError("raw request vazio")

        request_line = lines[0].strip()
        try:
            method, path, _ = request_line.split()
        except ValueError as exc:
            raise ValueError(f"linha de requisição inválida: {request_line}") from exc

        headers: Dict[str, str] = {}
        body_lines: List[str] = []
        parsing_headers = True

        for line in lines[1:]:
            if parsing_headers and not line.strip():
                parsing_headers = False
                continue

            if parsing_headers:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
            else:
                body_lines.append(line)

        body = "\n".join(body_lines) if body_lines else None

        url = path
        if not url.startswith("http://") and not url.startswith("https://"):
            url = self._build_url(url)

        headers.setdefault("Host", self.host)

        return method.upper(), url, headers, body

    def _evaluate_dsl(self, expressions: List[str], response: httpx.Response) -> bool:
        """Avalia expressões DSL simples."""
        if not expressions:
            return False

        body = response.text or ""
        headers = {k.lower(): v for k, v in response.headers.items()}
        status_code = response.status_code
        json_cache: Any = None

        def _normalize(source: Any) -> str:
            if source is None:
                return ""
            return str(source)

        def _contains(source: Any, needle: str) -> bool:
            return needle.lower() in _normalize(source).lower()

        def _icontains(source: Any, needle: str) -> bool:
            return _contains(source, needle)

        def _startswith(source: Any, prefix: str) -> bool:
            return _normalize(source).lower().startswith(prefix.lower())

        def _endswith(source: Any, suffix: str) -> bool:
            return _normalize(source).lower().endswith(suffix.lower())

        def _equals(left: Any, right: Any) -> bool:
            return _normalize(left).lower() == _normalize(right).lower()

        def _regex(pattern: str, source: Optional[str] = None) -> bool:
            target = source if source is not None else body
            return bool(re.search(pattern, target or "", re.IGNORECASE))

        def _header(name: str) -> Optional[str]:
            return headers.get(name.lower())

        def _count(source: Any, needle: str) -> int:
            return _normalize(source).lower().count(needle.lower())

        def _status_in(*codes: int) -> bool:
            return status_code in set(int(code) for code in codes)

        def _status_between(start: int, end: int) -> bool:
            return start <= status_code <= end

        def _json(path: str, default: Any = None) -> Any:
            nonlocal json_cache
            if json_cache is None:
                try:
                    json_cache = json.loads(body)
                except Exception:
                    json_cache = {}

            current = json_cache
            if not path:
                return current
            for part in path.split('.'):
                if isinstance(current, dict) and part in current:
                    current = current[part]
                elif isinstance(current, list):
                    try:
                        idx = int(part)
                        current = current[idx]
                    except (ValueError, IndexError):
                        return default
                else:
                    return default
            return current

        def _present(value: Any) -> bool:
            if value is None:
                return False
            if isinstance(value, str):
                return bool(value.strip())
            if isinstance(value, (list, dict, set, tuple)):
                return len(value) > 0
            return True

        env = {
            "body": body,
            "headers": headers,
            "status_code": status_code,
            "contains": _contains,
            "icontains": _icontains,
            "startswith": _startswith,
            "endswith": _endswith,
            "equals": _equals,
            "regex": _regex,
            "header": _header,
            "count": _count,
            "status_in": _status_in,
            "status_between": _status_between,
            "json_get": _json,
            "present": _present,
            "len": len,
            "any": any,
            "all": all,
            "status": lambda: status_code,
            "lower": lambda s: s.lower() if isinstance(s, str) else s,
            "upper": lambda s: s.upper() if isinstance(s, str) else s,
        }

        safe_globals = {"__builtins__": {}}

        for expression in expressions:
            expr = expression.strip()
            if not expr:
                continue
            try:
                if not bool(eval(expr, safe_globals, env)):
                    return False
            except Exception as exc:
                logger.debug("template.dsl.error", expression=expr, error=str(exc))
                return False

        return True
    
    def _get_response_part(self, response: httpx.Response, part: str) -> str:
        """Extrai parte específica da response."""
        if part == "body":
            return response.text
        elif part == "header":
            return str(response.headers)
        elif part == "all":
            return f"{response.headers}\n\n{response.text}"
        else:
            return response.text
    
    def _extract_data(self, extractors: List[Dict[str, Any]], response: httpx.Response) -> Dict[str, Any]:
        """Extrai dados da response."""
        extracted = {}
        
        for extractor in extractors:
            extractor_type = extractor.get("type", "regex")
            name = extractor.get("name", "data")
            part = extractor.get("part", "body")
            
            content = self._get_response_part(response, part)
            
            if extractor_type == "regex":
                regexes = extractor.get("regex", [])
                for regex in regexes:
                    match = re.search(regex, content, re.IGNORECASE)
                    if match:
                        if match.groups():
                            extracted[name] = match.group(1)
                        else:
                            extracted[name] = match.group(0)
            
            elif extractor_type == "kval":
                # Key-value extraction
                kval = extractor.get("kval", [])
                # Busca padrão key=value
                for key in kval:
                    pattern = f"{key}=([^&\\s]+)"
                    match = re.search(pattern, content)
                    if match:
                        extracted[key] = match.group(1)
            
            elif extractor_type == "json":
                try:
                    data_json = json.loads(content)
                except json.JSONDecodeError:
                    continue

                paths = extractor.get("json", [])
                if isinstance(paths, str):
                    paths = [paths]

                for path_expr in paths:
                    value = self._extract_from_json(data_json, path_expr)
                    if value is not None:
                        extracted[name] = value
        
        return extracted

    def _extract_from_json(self, data: Any, path_expr: str) -> Optional[Any]:
        """Suporte simples para extração JSON via notação ponto."""
        if not path_expr:
            return None

        current = data
        for part in path_expr.split('.'):
            if part == '':
                continue
            if isinstance(current, list):
                try:
                    index = int(part)
                    current = current[index]
                except (ValueError, IndexError):
                    return None
            elif isinstance(current, dict):
                if part not in current:
                    return None
                current = current.get(part)
            else:
                return None

        return current
    
    def _create_example_templates(self):
        """Cria templates de exemplo."""
        templates_dir = Path(self.templates_path)
        templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Template exemplo: Git exposure
        git_template = {
            "id": "git-config",
            "info": {
                "name": "Git Config Exposure",
                "severity": "high",
                "description": "Detects exposed .git/config file",
            },
            "requests": [
                {
                    "method": "GET",
                    "path": ["/.git/config"],
                }
            ],
            "matchers": [
                {
                    "type": "word",
                    "words": ["[core]", "[remote"],
                    "condition": "and",
                },
                {
                    "type": "status",
                    "status": [200],
                }
            ],
        }
        
        with open(templates_dir / "git-config.yaml", 'w') as f:
            yaml.dump(git_template, f)
        
        logger.info("template.examples.created", path=str(templates_dir))
    
    def export(self, findings: List[TemplateFinding], output: str):
        """Exporta findings para arquivo."""
        import json
        
        data = [
            {
                "template_id": f.template_id,
                "name": f.name,
                "severity": f.severity,
                "description": f.description,
                "matched_at": f.matched_at,
                "extracted_data": f.extracted_data,
            }
            for f in findings
        ]
        
        with open(output, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info("template.export.complete", file=output, count=len(findings))


__all__ = ["TemplateScanner", "Template", "TemplateFinding"]
