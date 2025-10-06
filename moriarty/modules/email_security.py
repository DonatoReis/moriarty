"""Validações avançadas de segurança de email."""
import asyncio
import hashlib
import ssl
from dataclasses import dataclass
from typing import List, Optional

import aiodns
import httpx
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class TLSARecord:
    """Registro TLSA (DANE)."""
    usage: int
    selector: int
    matching_type: int
    certificate_data: str


@dataclass
class ARCResult:
    """Resultado da validação ARC."""
    present: bool
    chain_valid: bool
    instances: int
    sealer: Optional[str] = None


@dataclass
class TLSGrade:
    """Avaliação TLS do servidor."""
    protocol: str  # TLSv1.2, TLSv1.3
    cipher: str
    grade: str  # A+, A, B, C, D, F
    supports_tls13: bool
    forward_secrecy: bool
    vulnerabilities: List[str]


@dataclass
class GreylistingStatus:
    """Status de greylisting."""
    detected: bool
    retry_after: Optional[int] = None  # segundos
    temp_fail_code: Optional[int] = None


class EmailSecurityChecker:
    """Verifica recursos avançados de segurança de email."""
    
    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout
        self._resolver = aiodns.DNSResolver(timeout=timeout)
    
    async def check_tlsa(self, domain: str, port: int = 25) -> List[TLSARecord]:
        """
        Verifica registros TLSA (DANE - DNS-based Authentication of Named Entities).
        
        Ex: _25._tcp.mail.example.com
        """
        tlsa_domain = f"_{port}._tcp.{domain}"
        
        try:
            logger.info("email.security.tlsa.check", domain=tlsa_domain)
            result = await self._resolver.query(tlsa_domain, "TLSA")
            
            if not isinstance(result, list):
                return []
            
            records = []
            for record in result:
                # Formato TLSA: usage selector matching_type certificate_data
                try:
                    usage = getattr(record, 'usage', 0)
                    selector = getattr(record, 'selector', 0)
                    matching_type = getattr(record, 'matching_type', 0)
                    cert_data = getattr(record, 'cert', '')
                    
                    records.append(TLSARecord(
                        usage=usage,
                        selector=selector,
                        matching_type=matching_type,
                        certificate_data=cert_data,
                    ))
                except Exception as e:
                    logger.warning("email.security.tlsa.parse_error", error=str(e))
            
            logger.info("email.security.tlsa.found", domain=tlsa_domain, count=len(records))
            return records
            
        except aiodns.error.DNSError:
            logger.debug("email.security.tlsa.not_found", domain=tlsa_domain)
            return []
    
    async def check_arc(self, mx_host: str) -> ARCResult:
        """
        Verifica suporte a ARC (Authenticated Received Chain).
        
        ARC é usado para preservar autenticação através de intermediários.
        Checamos via headers SMTP ou via consulta ao servidor.
        """
        # Simulação - em produção, faria uma conexão SMTP real
        # e verificaria os headers de uma mensagem test
        logger.info("email.security.arc.check", mx_host=mx_host)
        
        # Por agora, retorna placeholder
        # TODO: Implementar verificação real via SMTP
        return ARCResult(
            present=False,
            chain_valid=False,
            instances=0,
            sealer=None,
        )
    
    async def grade_tls(self, mx_host: str, port: int = 25) -> TLSGrade:
        """
        Avalia a qualidade da configuração TLS do servidor SMTP.
        
        Verifica:
        - Versão do protocolo (TLS 1.2, 1.3)
        - Cipher suites
        - Forward secrecy
        - Vulnerabilidades conhecidas
        """
        logger.info("email.security.tls_grade.start", mx_host=mx_host, port=port)
        
        vulnerabilities = []
        
        try:
            # Cria contexto SSL
            context = ssl.create_default_context()
            
            # Tenta conexão TLS
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(mx_host, port, ssl=context),
                timeout=self._timeout
            )
            
            # Obtém informações SSL
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object:
                protocol = ssl_object.version()
                cipher = ssl_object.cipher()
                
                supports_tls13 = protocol == 'TLSv1.3'
                
                # Verifica forward secrecy (PFS)
                cipher_name = cipher[0] if cipher else ""
                forward_secrecy = any(fs in cipher_name for fs in ['ECDHE', 'DHE'])
                
                # Determina grade
                if supports_tls13 and forward_secrecy:
                    grade = "A+"
                elif protocol == 'TLSv1.2' and forward_secrecy:
                    grade = "A"
                elif protocol == 'TLSv1.2':
                    grade = "B"
                elif protocol == 'TLSv1.1':
                    grade = "C"
                    vulnerabilities.append("TLS 1.1 deprecated")
                else:
                    grade = "F"
                    vulnerabilities.append("Insecure TLS version")
                
                # Verifica cipher fraco
                if cipher_name and ('RC4' in cipher_name or 'DES' in cipher_name):
                    vulnerabilities.append("Weak cipher detected")
                    grade = "F"
                
                writer.close()
                await writer.wait_closed()
                
                logger.info("email.security.tls_grade.complete", mx_host=mx_host, grade=grade, protocol=protocol)
                
                return TLSGrade(
                    protocol=protocol,
                    cipher=cipher_name,
                    grade=grade,
                    supports_tls13=supports_tls13,
                    forward_secrecy=forward_secrecy,
                    vulnerabilities=vulnerabilities,
                )
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.warning("email.security.tls_grade.error", mx_host=mx_host, error=str(e))
        
        # Fallback: sem TLS
        return TLSGrade(
            protocol="None",
            cipher="",
            grade="F",
            supports_tls13=False,
            forward_secrecy=False,
            vulnerabilities=["No TLS support detected"],
        )
    
    async def detect_greylisting(self, mx_host: str, sender: str, recipient: str) -> GreylistingStatus:
        """
        Detecta se o servidor usa greylisting.
        
        Greylisting temporariamente rejeita emails desconhecidos
        com código 4xx, esperando retry.
        """
        logger.info("email.security.greylisting.check", mx_host=mx_host)
        
        try:
            # Faz tentativa SMTP inicial
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(mx_host, 25),
                timeout=self._timeout
            )
            
            # Lê banner
            banner = await reader.read(1024)
            
            # EHLO
            writer.write(b"EHLO moriarty.local\r\n")
            await writer.drain()
            ehlo_response = await reader.read(1024)
            
            # MAIL FROM
            writer.write(f"MAIL FROM:<{sender}>\r\n".encode())
            await writer.drain()
            mail_response = await reader.read(1024)
            
            # RCPT TO
            writer.write(f"RCPT TO:<{recipient}>\r\n".encode())
            await writer.drain()
            rcpt_response = await reader.read(1024)
            
            writer.write(b"QUIT\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            
            # Analisa resposta
            rcpt_str = rcpt_response.decode('utf-8', errors='ignore')
            
            # Códigos 4xx indicam erro temporário (greylisting comum)
            if rcpt_str.startswith('4'):
                # Extrai código
                parts = rcpt_str.split()
                code = int(parts[0]) if parts else 450
                
                # Greylisting detectado
                logger.info("email.security.greylisting.detected", mx_host=mx_host, code=code)
                return GreylistingStatus(
                    detected=True,
                    temp_fail_code=code,
                    retry_after=300,  # Típico: 5 minutos
                )
            
            logger.info("email.security.greylisting.not_detected", mx_host=mx_host)
            return GreylistingStatus(detected=False)
            
        except Exception as e:
            logger.warning("email.security.greylisting.error", mx_host=mx_host, error=str(e))
            return GreylistingStatus(detected=False)


__all__ = [
    "EmailSecurityChecker",
    "TLSARecord",
    "ARCResult",
    "TLSGrade",
    "GreylistingStatus",
]
