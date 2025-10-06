"""Extração de telefones de perfis sociais."""
import re
from dataclasses import dataclass
from typing import List, Optional

import phonenumbers
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class PhoneNumber:
    """Número de telefone normalizado."""
    raw: str
    normalized: str  # E.164 format
    country_code: str
    national_number: str
    is_valid: bool
    is_mobile: bool
    carrier: Optional[str] = None
    location: Optional[str] = None


class PhoneExtractor:
    """Extrai e valida números de telefone."""
    
    # Padrões comuns de telefone
    PHONE_PATTERNS = [
        r'\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{1,4}[\s\-]?\d{1,9}',  # Internacional
        r'\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}',  # US/BR format
        r'\d{2}[\s\-]?\d{4,5}[\s\-]?\d{4}',  # BR format
        r'\d{10,15}',  # Números longos
    ]
    
    def extract_from_text(self, text: str, default_region: str = "US") -> List[PhoneNumber]:
        """
        Extrai números de telefone de um texto.
        
        Args:
            text: Texto para buscar
            default_region: Código do país padrão (ISO 3166-1 alpha-2)
        """
        if not text:
            return []
        
        logger.debug("phone.extract.start", text_length=len(text))
        
        phones = []
        seen = set()
        
        for pattern in self.PHONE_PATTERNS:
            matches = re.finditer(pattern, text)
            
            for match in matches:
                raw = match.group(0)
                
                # Remove duplicatas
                if raw in seen:
                    continue
                seen.add(raw)
                
                # Tenta parsear com phonenumbers
                try:
                    parsed = phonenumbers.parse(raw, default_region)
                    
                    if phonenumbers.is_valid_number(parsed):
                        normalized = phonenumbers.format_number(
                            parsed,
                            phonenumbers.PhoneNumberFormat.E164
                        )
                        
                        national = phonenumbers.format_number(
                            parsed,
                            phonenumbers.PhoneNumberFormat.NATIONAL
                        )
                        
                        is_mobile = phonenumbers.number_type(parsed) in [
                            phonenumbers.PhoneNumberType.MOBILE,
                            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE,
                        ]
                        
                        # Tenta obter carrier (operadora)
                        carrier = None
                        try:
                            from phonenumbers import carrier as carrier_module
                            carrier = carrier_module.name_for_number(parsed, "en")
                        except:
                            pass
                        
                        # Tenta obter localização
                        location = None
                        try:
                            from phonenumbers import geocoder
                            location = geocoder.description_for_number(parsed, "en")
                        except:
                            pass
                        
                        phone = PhoneNumber(
                            raw=raw,
                            normalized=normalized,
                            country_code=f"+{parsed.country_code}",
                            national_number=national,
                            is_valid=True,
                            is_mobile=is_mobile,
                            carrier=carrier if carrier else None,
                            location=location if location else None,
                        )
                        
                        phones.append(phone)
                        logger.debug("phone.extracted", phone=normalized, location=location)
                    
                except phonenumbers.NumberParseException:
                    # Número inválido, ignora
                    continue
        
        logger.info("phone.extract.complete", count=len(phones))
        return phones
    
    def extract_from_profile(self, profile_data: dict, default_region: str = "US") -> List[PhoneNumber]:
        """
        Extrai telefones de dados de perfil.
        
        Busca em campos comuns: bio, description, contact, etc.
        """
        phones = []
        
        # Campos comuns onde telefones aparecem
        fields_to_check = [
            "bio", "description", "about", "contact", "phone",
            "contact_info", "business_phone", "mobile", "tel",
        ]
        
        for field in fields_to_check:
            if field in profile_data and profile_data[field]:
                value = str(profile_data[field])
                extracted = self.extract_from_text(value, default_region)
                phones.extend(extracted)
        
        # Remove duplicatas
        unique_phones = {}
        for phone in phones:
            unique_phones[phone.normalized] = phone
        
        return list(unique_phones.values())


__all__ = [
    "PhoneExtractor",
    "PhoneNumber",
]
