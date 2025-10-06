from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx
import structlog

from ..models.entity import Entity
from ..models.types import EntityKind

logger = structlog.get_logger(__name__)


@dataclass(slots=True)
class SocialProfile:
    """Perfil encontrado em uma plataforma."""

    platform: str
    url: str
    username: Optional[str] = None
    user_id: Optional[str] = None
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    verified: bool = False
    confidence: float = 0.5
    metadata: Dict[str, Any] = None

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}


@dataclass(slots=True)
class EmailInvestigationResult:
    """Resultado de uma investigação profunda de email."""

    email: str
    normalized_email: str
    domain: str
    local_part: str
    
    # Gravatar
    gravatar_hash: str
    gravatar_profile: Optional[Dict[str, Any]] = None
    gravatar_avatar: Optional[str] = None
    
    # Social profiles
    social_profiles: List[SocialProfile] = None
    
    # Breaches
    breached: bool = False
    breach_count: int = 0
    breaches: List[Dict[str, Any]] = None
    
    # Linked data
    phone_numbers: List[str] = None
    websites: List[str] = None
    usernames: List[str] = None
    
    # Metadata
    total_platforms_found: int = 0
    search_timestamp: str = ""

    def __post_init__(self) -> None:
        if self.social_profiles is None:
            self.social_profiles = []
        if self.breaches is None:
            self.breaches = []
        if self.phone_numbers is None:
            self.phone_numbers = []
        if self.websites is None:
            self.websites = []
        if self.usernames is None:
            self.usernames = []


class EmailInvestigator:
    """Investiga email em múltiplas fontes."""

    def __init__(self, timeout: float = 8.0, user_agent: Optional[str] = None) -> None:
        self._timeout = timeout
        self._user_agent = user_agent or "Moriarty/0.1.0 (OSINT Client)"

    async def investigate(self, email: str) -> EmailInvestigationResult:
        """Executa investigação completa."""
        from datetime import datetime, timezone
        from email_validator import validate_email
        
        # Normaliza
        validated = validate_email(email, check_deliverability=False)
        normalized = validated.normalized or validated.email
        local_part, domain = normalized.lower().split("@", 1)
        
        # Gera hash Gravatar
        gravatar_hash = hashlib.md5(normalized.encode("utf-8")).hexdigest()
        
        # Executa investigações em paralelo
        tasks = [
            self._check_gravatar(gravatar_hash),
            self._check_social_profiles_smart(email, local_part),
            self._check_breaches_anon(email),
        ]
        
        gravatar_data, social_profiles, breach_data = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Processa Gravatar
        gravatar_profile = None
        gravatar_avatar = None
        if isinstance(gravatar_data, dict):
            gravatar_profile = gravatar_data
            gravatar_avatar = f"https://www.gravatar.com/avatar/{gravatar_hash}?s=200&d=404"
        
        # Processa social
        profiles: List[SocialProfile] = []
        if isinstance(social_profiles, list):
            profiles = social_profiles
        
        # Processa breaches
        breached = False
        breach_count = 0
        breaches = []
        if isinstance(breach_data, dict):
            breached = breach_data.get("breached", False)
            breach_count = breach_data.get("count", 0)
            breaches = breach_data.get("breaches", [])
        
        # Extrai dados agregados
        usernames = list(set(p.username for p in profiles if p.username))
        websites = list(set(p.metadata.get("website") for p in profiles if p.metadata.get("website")))
        
        result = EmailInvestigationResult(
            email=email,
            normalized_email=normalized,
            domain=domain,
            local_part=local_part,
            gravatar_hash=gravatar_hash,
            gravatar_profile=gravatar_profile,
            gravatar_avatar=gravatar_avatar,
            social_profiles=profiles,
            breached=breached,
            breach_count=breach_count,
            breaches=breaches,
            phone_numbers=[],
            websites=websites,
            usernames=usernames,
            total_platforms_found=len(profiles),
            search_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        
        return result

    async def _check_gravatar(self, gravatar_hash: str) -> Optional[Dict[str, Any]]:
        """Verifica perfil Gravatar."""
        url = f"https://www.gravatar.com/{gravatar_hash}.json"
        
        try:
            async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=False) as client:
                response = await client.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    return data.get("entry", [{}])[0] if data.get("entry") else None
        except Exception:
            pass
        
        return None

    async def _check_social_profiles_smart(
        self, email: str, local_part: str
    ) -> List[SocialProfile]:
        """Busca inteligente em redes sociais usando templates."""
        from ..dsl.loader import TemplateLoader
        from ..modules.template_executor import TemplateExecutor
        
        profiles: List[SocialProfile] = []
        
        # Carrega templates
        loader = TemplateLoader()
        loader.load_builtin()
        
        # Filtra apenas templates habilitados
        templates = [t for t in loader.list_templates() if t.enabled and not t.require_headless]
        
        if not templates:
            return profiles
        
        # Executa templates usando local_part como username
        executor = TemplateExecutor(timeout=self._timeout, user_agent=self._user_agent)
        
        # Limita a 20 sites mais relevantes para não demorar muito
        relevant_templates = templates[:20]
        
        semaphore = asyncio.Semaphore(10)  # Max 10 paralelas
        
        async def check_site(template: Any) -> Optional[SocialProfile]:
            async with semaphore:
                try:
                    result = await executor.execute(template, {"username": local_part})
                    
                    if result.exists and result.confidence > 0.5:
                        # Extrai dados relevantes
                        profile = SocialProfile(
                            platform=template.site,
                            url=result.url,
                            username=local_part,
                            display_name=result.extracted.get("name"),
                            bio=result.extracted.get("bio"),
                            avatar_url=result.extracted.get("avatar"),
                            confidence=result.confidence,
                            metadata={
                                "website": result.extracted.get("website"),
                                "location": result.extracted.get("location"),
                                "followers": result.extracted.get("followers"),
                            },
                        )
                        return profile
                except Exception:
                    pass
            
            return None
        
        tasks = [check_site(t) for t in relevant_templates]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filtra resultados válidos
        for result in results:
            if isinstance(result, SocialProfile):
                profiles.append(result)
        
        return profiles

    async def _check_breaches_anon(self, email: str) -> Dict[str, Any]:
        """Verifica breaches usando HIBP k-anonymity."""
        # HIBP k-anonymity: hash SHA-1, envia apenas primeiros 5 chars
        sha1_hash = hashlib.sha1(email.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(url, headers={"User-Agent": self._user_agent})
                
                if response.status_code == 200:
                    # Procura pelo suffix na resposta
                    lines = response.text.split("\n")
                    for line in lines:
                        if line.startswith(suffix):
                            count = int(line.split(":")[1])
                            logger.warning("breach.found", email=email, count=count)
                            return {
                                "breached": True,
                                "count": count,
                                "breaches": [{"source": "HIBP", "occurrences": count}],
                            }
        except Exception as exc:
            logger.debug("breach.check.error", error=str(exc))
        
        return {"breached": False, "count": 0, "breaches": []}


__all__ = ["EmailInvestigator", "EmailInvestigationResult", "SocialProfile"]
