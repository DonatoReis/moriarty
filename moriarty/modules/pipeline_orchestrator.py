"""Pipeline Orchestrator - Execução declarativa de ataques via YAML."""
import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import structlog
import yaml
from rich.console import Console
from rich.tree import Tree

from moriarty.core.config_manager import config_manager
from moriarty.modules.passive_recon import PassiveRecon
from moriarty.modules.port_scanner import PortScanner
from moriarty.modules.web_crawler import WebCrawler

logger = structlog.get_logger(__name__)
console = Console()


@dataclass
class PipelineStage:
    """Stage do pipeline."""
    name: str
    module: str
    config: Dict[str, Any]
    depends_on: List[str] = None
    condition: Optional[str] = None


@dataclass
class PipelineResult:
    """Resultado de execução do pipeline."""
    stage: str
    success: bool
    output: Any
    duration: float


class PipelineOrchestrator:
    """
    Orquestrador de pipelines declarativos.
    
    Exemplo de pipeline.yaml:
    
    ```yaml
    name: "Full Recon Pipeline"
    target: "example.com"
    
    variables:
      wordlist: "/path/to/wordlist.txt"
      threads: 20
    
    stages:
      - name: "DNS Discovery"
        module: "dns"
        config:
          records: ["A", "AAAA", "MX", "TXT"]
      
      - name: "Subdomain Enum"
        module: "subdiscover"
        depends_on: ["DNS Discovery"]
        config:
          sources: ["crtsh", "wayback"]
          validate: true
      
      - name: "Port Scan"
        module: "ports"
        depends_on: ["Subdomain Enum"]
        config:
          ports: "common"
          stealth: 2
      
      - name: "Template Scan"
        module: "template-scan"
        depends_on: ["Port Scan"]
        condition: "len(previous.open_ports) > 0"
        config:
          severity: ["critical", "high"]
    ```
    """
    
    def __init__(
        self,
        pipeline_file: str,
        target_override: Optional[str] = None,
        vars_file: Optional[str] = None,
        dry_run: bool = False,
        log_file: Optional[str] = None,
        checkpoint_file: Optional[str] = None,
        resume: bool = True,
    ):
        self.pipeline_file = pipeline_file
        self.target_override = target_override
        self.vars_file = vars_file
        self.dry_run = dry_run
        self.resume_enabled = resume
        
        self.pipeline_data: Dict[str, Any] = {}
        self.stages: List[PipelineStage] = []
        self.results: List[PipelineResult] = []
        self.variables: Dict[str, Any] = {}
        self.stage_results: Dict[str, PipelineResult] = {}
        self.default_retries: int = 1
        self.config = config_manager
        self.notification_config = getattr(self.config, "notifications", None) if self.config else None

        base_dir = Path(self.config.config_dir) if self.config else Path.home() / ".moriarty"

        logs_dir = base_dir / "logs"
        checkpoints_dir = base_dir / "checkpoints"
        logs_dir.mkdir(parents=True, exist_ok=True)
        checkpoints_dir.mkdir(parents=True, exist_ok=True)

        self.log_file_path = Path(log_file) if log_file else logs_dir / "pipeline.log"
        self.checkpoint_path = (
            Path(checkpoint_file)
            if checkpoint_file
            else checkpoints_dir / f"{Path(self.pipeline_file).stem}.json"
        )
    
    async def run(self):
        """Executa pipeline."""
        logger.info("pipeline.start", file=self.pipeline_file)
        self._log_event("pipeline_start", file=self.pipeline_file)
        
        # Carrega pipeline
        self._load_pipeline()
        
        # Carrega variáveis
        self._load_variables()
        
        if self.resume_enabled:
            self._load_checkpoint()
        
        # Mostra resumo
        self._show_summary()
        
        if self.dry_run:
            console.print("[yellow]🔍 Dry run - não executando stages[/yellow]")
            return
        
        # Executa stages em ordem
        await self._execute_stages()
        
        # Mostra resultados
        self._show_results()
        await self._notify_pipeline_summary()
        self._finalize_checkpoint()
        self._log_event(
            "pipeline_complete",
            success=all(result.success for result in self.results) if self.results else True,
            total=len(self.results),
        )
    
    def _load_pipeline(self):
        """Carrega arquivo de pipeline."""
        try:
            with open(self.pipeline_file, 'r') as f:
                self.pipeline_data = yaml.safe_load(f)
            
            # Override target se fornecido
            if self.target_override:
                self.pipeline_data["target"] = self.target_override
            
            # Parse stages
            for stage_data in self.pipeline_data.get("stages", []):
                stage = PipelineStage(
                    name=stage_data["name"],
                    module=stage_data["module"],
                    config=stage_data.get("config", {}),
                    depends_on=stage_data.get("depends_on", []),
                    condition=stage_data.get("condition"),
                )
                self.stages.append(stage)
            
            logger.info("pipeline.loaded", stages=len(self.stages))
            
        except Exception as e:
            logger.error("pipeline.load.error", error=str(e))
            raise
    
    def _load_variables(self):
        """Carrega variáveis do pipeline e arquivo externo."""
        # Variáveis do pipeline
        self.variables = self.pipeline_data.get("variables", {})
        
        # Variáveis de arquivo externo
        if self.vars_file:
            try:
                with open(self.vars_file, 'r') as f:
                    external_vars = yaml.safe_load(f)
                    self.variables.update(external_vars)
            except Exception as e:
                logger.warning("pipeline.vars.load.error", file=self.vars_file, error=str(e))
    
    def _show_summary(self):
        """Mostra resumo do pipeline."""
        tree = Tree(f"[bold cyan]🔄 Pipeline: {self.pipeline_data.get('name', 'Unnamed')}[/bold cyan]")
        
        tree.add(f"[dim]Target:[/dim] {self.pipeline_data.get('target', 'N/A')}")
        tree.add(f"[dim]Stages:[/dim] {len(self.stages)}")
        
        if self.variables:
            vars_node = tree.add("[dim]Variables:[/dim]")
            for key, value in self.variables.items():
                vars_node.add(f"{key}: {value}")
        
        stages_node = tree.add("[bold]Stages:[/bold]")
        for stage in self.stages:
            stage_label = f"{stage.name} [dim]({stage.module})[/dim]"
            stage_node = stages_node.add(stage_label)
            
            if stage.depends_on:
                stage_node.add(f"[dim]Depends on: {', '.join(stage.depends_on)}[/dim]")
            
            if stage.condition:
                stage_node.add(f"[dim]Condition: {stage.condition}[/dim]")
        
        console.print(tree)
        console.print()
    
    async def _execute_stages(self):
        """Executa stages do pipeline com paralelismo e retries."""
        pending = {
            stage.name: stage
            for stage in self.stages
            if stage.name not in self.stage_results
            or not self.stage_results[stage.name].success
        }
        running: Dict[asyncio.Task, PipelineStage] = {}

        while pending or running:
            ready: List[PipelineStage] = []

            for stage_name, stage in list(pending.items()):
                if not self._dependencies_met(stage):
                    continue

                if stage.condition and not self._evaluate_condition(stage):
                    logger.info("pipeline.stage.skip.condition", stage=stage.name)
                    result = PipelineResult(
                        stage=stage.name,
                        success=True,
                        output="skipped (condition)",
                        duration=0.0,
                    )
                    self.results.append(result)
                    self.stage_results[stage.name] = result
                    pending.pop(stage_name)
                    continue

                ready.append(stage)
                pending.pop(stage_name)

            for stage in ready:
                task = asyncio.create_task(self._execute_stage_with_retry(stage))
                running[task] = stage

            if not running:
                # Nenhuma stage pronta (dependências não satisfeitas)
                break

            done, _ = await asyncio.wait(running.keys(), return_when=asyncio.FIRST_COMPLETED)

            for task in done:
                stage = running.pop(task)
                try:
                    result = await task
                except Exception as exc:  # pragma: no cover - fallback seguro
                    logger.error("pipeline.stage.unhandled", stage=stage.name, error=str(exc))
                    result = PipelineResult(
                        stage=stage.name,
                        success=False,
                        output=str(exc),
                        duration=0.0,
                    )

            self.results.append(result)
            self.stage_results[stage.name] = result
            self._persist_checkpoint(result)

            if result.success:
                console.print(f"[green]✓ Completo:[/green] {stage.name} [{result.duration:.2f}s]")
            else:
                console.print(f"[red]✗ Falhou:[/red] {stage.name}")

        for stage_name, stage in pending.items():
            logger.warning("pipeline.stage.unexecuted", stage=stage.name)

    def _dependencies_met(self, stage: PipelineStage) -> bool:
        """Verifica se dependências do stage já foram executadas."""
        if not stage.depends_on:
            return True
        return all(dep in self.stage_results for dep in stage.depends_on)

    async def _execute_stage_with_retry(self, stage: PipelineStage) -> PipelineResult:
        """Executa stage com política de retry."""
        retries = int(stage.config.get("retries", self.default_retries))
        delay = float(stage.config.get("retry_delay", 2.0))
        attempt = 0
        last_result: Optional[PipelineResult] = None

        while attempt <= retries:
            await self._notify_stage_start(stage, attempt)
            self._log_event("stage_start", stage=stage.name, attempt=attempt)
            result = await self._execute_stage(stage, attempt=attempt)

            if result.success:
                await self._notify_stage_end(stage, result)
                self._log_event(
                    "stage_complete",
                    stage=stage.name,
                    success=True,
                    duration=result.duration,
                )
                return result

            last_result = result
            attempt += 1

            if attempt <= retries:
                logger.warning("pipeline.stage.retry", stage=stage.name, attempt=attempt)
                await asyncio.sleep(delay)

        await self._notify_stage_end(stage, last_result or result)
        self._log_event(
            "stage_complete",
            stage=stage.name,
            success=False,
            duration=(last_result or result).duration if (last_result or result) else 0.0,
        )
        return last_result or result

    async def _execute_stage(self, stage: PipelineStage, attempt: int = 0) -> PipelineResult:
        """Executa uma stage."""
        import time
        start = time.time()

        try:
            label = stage.name if attempt == 0 else f"{stage.name} (retry {attempt})"
            console.print(f"[cyan]▶ Executando:[/cyan] {label}")

            # Substitui variáveis no config
            config = self._substitute_variables(stage.config)
            
            # Mapeamento de módulos
            if stage.module == "dns":
                output = await self._run_dns(config)
            elif stage.module == "subdiscover":
                output = await self._run_subdiscover(config)
            elif stage.module == "ports":
                output = await self._run_ports(config)
            elif stage.module == "template-scan":
                output = await self._run_template_scan(config)
            elif stage.module == "wayback":
                output = await self._run_wayback(config)
            elif stage.module == "passive":
                output = await self._run_passive(config)
            elif stage.module == "crawl":
                output = await self._run_crawl(config)
            else:
                logger.warning("pipeline.stage.unknown", module=stage.module)
                output = None

            duration = time.time() - start

            return PipelineResult(
                stage=stage.name,
                success=True,
                output=output,
                duration=duration,
            )
            
        except Exception as e:
            logger.error("pipeline.stage.error", stage=stage.name, error=str(e))
            duration = time.time() - start
            
            return PipelineResult(
                stage=stage.name,
                success=False,
                output=str(e),
                duration=duration,
            )
    
    def _substitute_variables(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Substitui variáveis no config."""
        import re
        
        def replace_var(match):
            var_name = match.group(1)
            return str(self.variables.get(var_name, match.group(0)))
        
        # Converte para string, substitui, converte de volta
        config_str = str(config)
        config_str = re.sub(r'\$\{(\w+)\}', replace_var, config_str)
        
        # Eval seguro (simplificado)
        try:
            return eval(config_str)
        except:
            return config
    
    def _evaluate_condition(self, stage: PipelineStage) -> bool:
        """Avalia condição booleana do stage."""
        if not stage.condition:
            return True

        try:
            previous = None
            if self.stage_results:
                previous = self.stage_results[next(reversed(self.stage_results))]

            context = {
                "len": len,
                "any": any,
                "all": all,
                "previous": previous,
                "results": self.stage_results,
                "stage_result": lambda name: self.stage_results.get(name),
            }

            return bool(eval(stage.condition, {"__builtins__": {}}, context))
        except Exception as e:
            logger.warning("pipeline.stage.condition_error", stage=stage.name, error=str(e))
            return False

    def _notifications_enabled(self) -> bool:
        """Retorna se notificações estão habilitadas."""
        return bool(
            self.notification_config
            and getattr(self.notification_config, "enabled", False)
            and (
                getattr(self.notification_config, "slack_enabled", False)
                or getattr(self.notification_config, "discord_enabled", False)
                or getattr(self.notification_config, "telegram_enabled", False)
            )
        )

    async def _notify_stage_start(self, stage: PipelineStage, attempt: int) -> None:
        """Envia notificação de início de stage."""
        if not self._notifications_enabled():
            return

        message = f"Stage '{stage.name}' iniciado"
        if attempt:
            message += f" (tentativa {attempt + 1})"

        await self._send_notification(message, level="info")

    async def _notify_stage_end(self, stage: PipelineStage, result: PipelineResult) -> None:
        """Envia notificação de conclusão de stage."""
        if not self._notifications_enabled():
            return

        status = "sucesso" if result and result.success else "falha"
        duration = f"{result.duration:.2f}s" if result else "0s"
        snippet = ""
        if result and isinstance(result.output, str) and result.output:
            snippet = f" - {result.output[:120]}"

        message = f"Stage '{stage.name}' finalizada com {status} em {duration}{snippet}"
        level = "success" if result and result.success else "error"
        await self._send_notification(message, level=level)

    async def _notify_pipeline_summary(self) -> None:
        """Envia resumo final do pipeline."""
        if not self._notifications_enabled():
            return

        total = len(self.results)
        success = sum(1 for item in self.results if item.success)
        message = (
            f"Pipeline '{self.pipeline_data.get('name', 'Unnamed')}' finalizado: "
            f"{success}/{total} stages com sucesso."
        )
        await self._send_notification(message, level="info")

    async def _send_notification(self, message: str, level: str = "info") -> None:
        """Envio de notificações para canais configurados."""
        if not self._notifications_enabled():
            return

        notif = self.notification_config
        title = self.pipeline_data.get('name', 'Moriarty Pipeline')
        tasks = []

        async with httpx.AsyncClient(timeout=5.0) as client:
            if getattr(notif, "slack_enabled", False) and notif.slack_webhook:
                tasks.append(
                    client.post(
                        notif.slack_webhook,
                        json={"text": f"[{level.upper()}] {title}: {message}"},
                    )
                )

            if getattr(notif, "discord_enabled", False) and notif.discord_webhook:
                tasks.append(
                    client.post(
                        notif.discord_webhook,
                        json={"content": f"[{level.upper()}] {title}: {message}"},
                    )
                )

            if (
                getattr(notif, "telegram_enabled", False)
                and notif.telegram_token
                and notif.telegram_chat_id
            ):
                telegram_url = f"https://api.telegram.org/bot{notif.telegram_token}/sendMessage"
                tasks.append(
                    client.post(
                        telegram_url,
                        data={
                            "chat_id": notif.telegram_chat_id,
                            "text": f"[{level.upper()}] {title}: {message}",
                        },
                    )
                )

            if not tasks:
                return

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for response in responses:
                if isinstance(response, Exception):
                    logger.debug("pipeline.notify.error", error=str(response))
                elif getattr(response, "status_code", 200) >= 400:
                    body = getattr(response, "text", "")
                    logger.debug(
                        "pipeline.notify.http_error",
                        status=response.status_code,
                        body=body[:200],
                    )

    def _load_checkpoint(self) -> None:
        if not self.resume_enabled or not self.checkpoint_path.exists():
            return

        try:
            with self.checkpoint_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)

            for entry in data.get("stages", []):
                stage_name = entry.get("stage")
                if not stage_name:
                    continue
                result = PipelineResult(
                    stage=stage_name,
                    success=bool(entry.get("success")),
                    output=entry.get("output"),
                    duration=float(entry.get("duration", 0.0)),
                )
                self.stage_results[stage_name] = result
                if result.success:
                    self.results.append(result)

            if self.stage_results:
                self._log_event(
                    "checkpoint_loaded",
                    stages=len(self.stage_results),
                    path=str(self.checkpoint_path),
                )

        except Exception as exc:
            logger.warning("pipeline.checkpoint.load_error", error=str(exc))

    def _persist_checkpoint(self, result: PipelineResult) -> None:
        if not self.resume_enabled:
            return

        payload = {
            "pipeline": self.pipeline_data.get("name", "Unnamed"),
            "stages": [
                {
                    "stage": r.stage,
                    "success": r.success,
                    "duration": r.duration,
                    "output": self._summarize_output(r.output),
                }
                for r in self.stage_results.values()
            ],
        }

        try:
            with self.checkpoint_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.warning("pipeline.checkpoint.save_error", error=str(exc))

    def _finalize_checkpoint(self) -> None:
        if not self.resume_enabled:
            return

        all_success = all(result.success for result in self.results) if self.results else False
        if all_success and self.checkpoint_path.exists():
            try:
                self.checkpoint_path.unlink()
                self._log_event("checkpoint_cleared", path=str(self.checkpoint_path))
            except Exception as exc:
                logger.debug("pipeline.checkpoint.cleanup_error", error=str(exc))

    def _summarize_output(self, output: Any) -> Any:
        if output is None:
            return None
        if isinstance(output, (str, int, float, bool)):
            text = str(output)
        else:
            text = str(output)
        return text[:2000]

    def _log_event(self, event: str, **payload: Any) -> None:
        if not self.log_file_path:
            return
        entry = {
            "event": event,
            "timestamp": time.time(),
            **payload,
        }
        try:
            with self.log_file_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.debug("pipeline.log.error", error=str(exc))

    async def _run_dns(self, config: Dict[str, Any]) -> Any:
        """Executa módulo DNS."""
        from moriarty.net.dns_client import DNSClient

        client = DNSClient()
        result = await client.lookup_domain(self.pipeline_data["target"])
        return result
    
    async def _run_subdiscover(self, config: Dict[str, Any]) -> Any:
        """Executa subdomain discovery."""
        from moriarty.modules.subdomain_discovery import SubdomainDiscovery
        
        discovery = SubdomainDiscovery(
            domain=self.pipeline_data["target"],
            sources=config.get("sources"),
            validate=config.get("validate", True),
        )
        return await discovery.discover()
    
    async def _run_ports(self, config: Dict[str, Any]) -> Any:
        """Executa port scan."""
        profile = config.get("profile", "quick")
        concurrency = int(config.get("concurrency", 200))
        timeout = float(config.get("timeout", 1.5))

        scanner = PortScanner(
            target=self.pipeline_data["target"],
            profile=profile,
            concurrency=concurrency,
            timeout=timeout,
        )
        results = await scanner.scan()
        return {
            "profile": profile,
            "results": [r.__dict__ for r in results],
        }

    async def _run_template_scan(self, config: Dict[str, Any]) -> Any:
        """Executa template scan."""
        from moriarty.modules.template_scanner import TemplateScanner

        scanner = TemplateScanner(
            target=self.pipeline_data["target"],
            severity_filter=config.get("severity"),
        )
        return await scanner.scan()

    async def _run_wayback(self, config: Dict[str, Any]) -> Any:
        """Executa wayback discovery."""
        from moriarty.modules.wayback_discovery import WaybackDiscovery

        wayback = WaybackDiscovery(
            domain=self.pipeline_data["target"],
            filter_extensions=config.get("filter_extensions"),
            filter_status_codes=config.get("filter_status_codes"),
        )
        return await wayback.discover()

    async def _run_passive(self, config: Dict[str, Any]) -> Any:
        """Executa coleta passiva utilizando PassiveRecon."""
        recon = PassiveRecon(self.pipeline_data["target"], timeout=float(config.get("timeout", 15.0)))
        try:
            result = await recon.collect()
            return result.to_dict()
        finally:
            await recon.close()

    async def _run_crawl(self, config: Dict[str, Any]) -> Any:
        """Executa crawler leve."""
        base_url = config.get("base_url") or f"https://{self.pipeline_data['target']}"
        crawler = WebCrawler(
            base_url=base_url,
            max_pages=int(config.get("max_pages", 100)),
            max_depth=int(config.get("max_depth", 2)),
            concurrency=int(config.get("concurrency", 10)),
            follow_subdomains=bool(config.get("follow_subdomains", False)),
        )
        try:
            pages = await crawler.crawl()
            return {url: page.__dict__ for url, page in pages.items()}
        finally:
            await crawler.close()
    
    def _show_results(self):
        """Mostra resultados do pipeline."""
        console.print("\n[bold]📊 Resultados:[/bold]\n")
        
        for result in self.results:
            status = "✓" if result.success else "✗"
            color = "green" if result.success else "red"
            console.print(f"[{color}]{status} {result.stage}[/{color}] - {result.duration:.2f}s")
        
        successful = sum(1 for r in self.results if r.success)
        console.print(f"\n[cyan]Total:[/cyan] {successful}/{len(self.results)} stages bem-sucedidos")


__all__ = ["PipelineOrchestrator", "PipelineStage", "PipelineResult"]
