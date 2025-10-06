"""Hashing perceptual de avatares para matching."""
import hashlib
from dataclasses import dataclass
from io import BytesIO
from typing import Optional

import httpx
import structlog
from PIL import Image

logger = structlog.get_logger(__name__)


@dataclass
class AvatarHash:
    """Hash perceptual de avatar."""
    url: str
    phash: str  # Perceptual hash (64 bits hex)
    ahash: str  # Average hash (64 bits hex)
    dhash: str  # Difference hash (64 bits hex)
    size: tuple  # (width, height)
    format: str  # JPEG, PNG, etc.


class AvatarHasher:
    """Cria hashes perceptuais de avatares para comparação."""
    
    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout
    
    async def hash_avatar(self, url: str) -> Optional[AvatarHash]:
        """
        Baixa e cria hashes perceptuais de um avatar.
        
        Hashes perceptuais permitem:
        - Encontrar avatares similares mesmo com pequenas modificações
        - Detectar mesma pessoa usando avatares levemente diferentes
        - Comparar avatares em diferentes resoluções
        """
        logger.info("avatar.hash.start", url=url)
        
        try:
            # Baixa imagem
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                image_data = response.content
            
            # Abre com PIL
            image = Image.open(BytesIO(image_data))
            
            # Redimensiona para processamento
            image = image.convert("RGB")
            
            # Calcula hashes
            phash = self._perceptual_hash(image)
            ahash = self._average_hash(image)
            dhash = self._difference_hash(image)
            
            logger.info("avatar.hash.complete", url=url, phash=phash[:16])
            
            return AvatarHash(
                url=url,
                phash=phash,
                ahash=ahash,
                dhash=dhash,
                size=image.size,
                format=image.format or "Unknown",
            )
            
        except Exception as e:
            logger.warning("avatar.hash.error", url=url, error=str(e))
            return None
    
    def _perceptual_hash(self, image: Image.Image, hash_size: int = 8) -> str:
        """
        Calcula pHash (perceptual hash).
        
        Algoritmo:
        1. Redimensiona para hash_size x hash_size
        2. Converte para grayscale
        3. Calcula DCT (Discrete Cosine Transform)
        4. Extrai top-left 8x8 excluindo DC
        5. Compara com mediana
        """
        # Redimensiona
        image = image.resize((hash_size * 4, hash_size * 4), Image.LANCZOS)
        image = image.convert("L")  # Grayscale
        
        # Simplificação: usa average hash como aproximação de pHash
        # Em produção, implementar DCT real ou usar biblioteca imagehash
        image = image.resize((hash_size, hash_size), Image.LANCZOS)
        pixels = list(image.getdata())
        
        avg = sum(pixels) / len(pixels)
        
        # Cria hash binário
        bits = "".join("1" if pixel > avg else "0" for pixel in pixels)
        
        # Converte para hex
        hash_hex = hex(int(bits, 2))[2:].zfill(16)
        
        return hash_hex
    
    def _average_hash(self, image: Image.Image, hash_size: int = 8) -> str:
        """
        Calcula aHash (average hash).
        
        Algoritmo:
        1. Redimensiona para hash_size x hash_size
        2. Converte para grayscale
        3. Calcula média dos pixels
        4. Cada pixel > média = 1, senão 0
        """
        image = image.resize((hash_size, hash_size), Image.LANCZOS)
        image = image.convert("L")
        
        pixels = list(image.getdata())
        avg = sum(pixels) / len(pixels)
        
        bits = "".join("1" if pixel > avg else "0" for pixel in pixels)
        hash_hex = hex(int(bits, 2))[2:].zfill(16)
        
        return hash_hex
    
    def _difference_hash(self, image: Image.Image, hash_size: int = 8) -> str:
        """
        Calcula dHash (difference hash).
        
        Algoritmo:
        1. Redimensiona para (hash_size+1) x hash_size
        2. Converte para grayscale
        3. Compara cada pixel com o próximo
        4. pixel[i] > pixel[i+1] = 1, senão 0
        """
        image = image.resize((hash_size + 1, hash_size), Image.LANCZOS)
        image = image.convert("L")
        
        pixels = list(image.getdata())
        
        bits = ""
        for row in range(hash_size):
            for col in range(hash_size):
                index = row * (hash_size + 1) + col
                left = pixels[index]
                right = pixels[index + 1]
                bits += "1" if left > right else "0"
        
        hash_hex = hex(int(bits, 2))[2:].zfill(16)
        
        return hash_hex
    
    def compare_hashes(self, hash1: str, hash2: str) -> int:
        """
        Compara dois hashes e retorna distância de Hamming.
        
        Distância 0 = idênticos
        Distância < 10 = muito similares
        Distância < 20 = similares
        Distância > 20 = diferentes
        """
        if len(hash1) != len(hash2):
            return 64  # Máxima distância
        
        # Converte para binário
        bin1 = bin(int(hash1, 16))[2:].zfill(64)
        bin2 = bin(int(hash2, 16))[2:].zfill(64)
        
        # Calcula distância de Hamming
        distance = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))
        
        return distance
    
    def is_similar(self, hash1: str, hash2: str, threshold: int = 10) -> bool:
        """Verifica se dois avatares são similares."""
        distance = self.compare_hashes(hash1, hash2)
        return distance <= threshold


__all__ = [
    "AvatarHasher",
    "AvatarHash",
]
