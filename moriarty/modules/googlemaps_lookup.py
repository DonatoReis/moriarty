"""Busca de reviews no Google Maps."""
import re
from dataclasses import dataclass
from typing import List, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class GoogleMapsReview:
    """Review do Google Maps."""
    author_name: str
    author_url: Optional[str]
    rating: int  # 1-5
    text: str
    time: str
    profile_photo_url: Optional[str]


@dataclass
class GoogleMapsProfile:
    """Perfil de usuário no Google Maps."""
    name: str
    profile_url: str
    reviews_count: int
    photos_count: int
    reviews: List[GoogleMapsReview]
    local_guide_level: Optional[int] = None


class GoogleMapsLookup:
    """Busca informações no Google Maps."""
    
    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout
    
    async def search_reviewer(self, name: str) -> Optional[GoogleMapsProfile]:
        """
        Busca reviews públicos de um nome no Google Maps.
        
        Nota: Esta é uma implementação simplificada.
        Google Maps requer API key para buscas completas.
        """
        logger.info("googlemaps.search", name=name)
        
        try:
            # Search via Google (scraping básico - em produção usar API oficial)
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                # Busca no Google por reviews
                search_url = f"https://www.google.com/search"
                params = {
                    "q": f"{name} google maps reviews",
                }
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                }
                
                response = await client.get(search_url, params=params, headers=headers, follow_redirects=True)
                
                # Parse HTML para extrair dados (simplificado)
                html = response.text
                
                # Extrai URLs de perfis do Google Maps
                profile_urls = re.findall(r'https://www\.google\.com/maps/contrib/\d+', html)
                
                if not profile_urls:
                    logger.info("googlemaps.not_found", name=name)
                    return None
                
                profile_url = profile_urls[0]
                
                # Busca o perfil
                profile_response = await client.get(profile_url, headers=headers)
                profile_html = profile_response.text
                
                # Extração básica (em produção, usar parser HTML robusto)
                reviews_match = re.search(r'(\d+)\s+reviews?', profile_html, re.IGNORECASE)
                reviews_count = int(reviews_match.group(1)) if reviews_match else 0
                
                photos_match = re.search(r'(\d+)\s+photos?', profile_html, re.IGNORECASE)
                photos_count = int(photos_match.group(1)) if photos_match else 0
                
                logger.info("googlemaps.found", name=name, reviews=reviews_count, photos=photos_count)
                
                return GoogleMapsProfile(
                    name=name,
                    profile_url=profile_url,
                    reviews_count=reviews_count,
                    photos_count=photos_count,
                    reviews=[],  # Populado com scraping mais profundo
                    local_guide_level=None,
                )
                
        except Exception as e:
            logger.warning("googlemaps.error", name=name, error=str(e))
            return None


__all__ = [
    "GoogleMapsLookup",
    "GoogleMapsProfile",
    "GoogleMapsReview",
]
