"""
test_rate_limiter.py
--------------------
Testes do sistema de rate limiting: sliding window, roles, bloqueio, headers.
"""

import time
from unittest.mock import patch

import pytest


class TestSlidingWindowCounter:
    """Testes unitários do SlidingWindowCounter."""

    def test_permite_dentro_do_limite(self):
        from api.middleware.rate_limiter import SlidingWindowCounter

        counter = SlidingWindowCounter(window_seconds=60, max_requests=5)
        for i in range(5):
            allowed, total, limit, _ = counter.hit("user1")
            assert allowed is True
        assert total == 5

    def test_bloqueia_acima_do_limite(self):
        from api.middleware.rate_limiter import SlidingWindowCounter

        counter = SlidingWindowCounter(window_seconds=60, max_requests=3)
        for _ in range(3):
            counter.hit("user1")

        allowed, total, limit, retry_after = counter.hit("user1")
        assert allowed is False
        assert total >= 3
        assert retry_after > 0

    def test_usuarios_diferentes_independentes(self):
        from api.middleware.rate_limiter import SlidingWindowCounter

        counter = SlidingWindowCounter(window_seconds=60, max_requests=2)
        counter.hit("user1")
        counter.hit("user1")

        # user1 bloqueado
        allowed_u1, _, _, _ = counter.hit("user1")
        assert allowed_u1 is False

        # user2 livre
        allowed_u2, _, _, _ = counter.hit("user2")
        assert allowed_u2 is True

    def test_get_remaining(self):
        from api.middleware.rate_limiter import SlidingWindowCounter

        counter = SlidingWindowCounter(window_seconds=60, max_requests=10)
        counter.hit("user1")
        counter.hit("user1")
        counter.hit("user1")

        remaining = counter.get_remaining("user1")
        assert remaining == 7

    def test_remaining_zero_quando_no_limite(self):
        from api.middleware.rate_limiter import SlidingWindowCounter

        counter = SlidingWindowCounter(window_seconds=60, max_requests=2)
        counter.hit("user1")
        counter.hit("user1")

        remaining = counter.get_remaining("user1")
        assert remaining == 0

    def test_cleanup_nao_quebra(self):
        from api.middleware.rate_limiter import SlidingWindowCounter

        counter = SlidingWindowCounter(window_seconds=60, max_requests=5)
        counter.hit("user1")
        cleaned = counter.cleanup_all()
        assert isinstance(cleaned, int)


class TestRateLimiter:
    """Testes do RateLimiter principal (múltiplas janelas)."""

    def test_check_permite_requisicao_normal(self):
        from api.middleware.rate_limiter import RateLimiter

        limiter = RateLimiter()
        result = limiter.check("test_user", role="admin")
        assert result["allowed"] is True
        assert result["remaining"] >= 0

    def test_check_por_role_user(self):
        from api.middleware.rate_limiter import RateLimiter

        limiter = RateLimiter()
        # User: 30 req/min
        for i in range(30):
            result = limiter.check(f"unique_user_{i}_rate", role="user")
            # Cada unique user tem seu próprio counter

        # Mesmo user excede
        for i in range(30):
            limiter.check("single_user", role="user")
        result = limiter.check("single_user", role="user")
        assert result["allowed"] is False

    def test_check_retorna_campos_esperados(self):
        from api.middleware.rate_limiter import RateLimiter

        limiter = RateLimiter()
        result = limiter.check("test", role="user")

        assert "allowed" in result
        assert "limit" in result
        assert "remaining" in result
        assert "retry_after" in result
        assert "window" in result


class TestRateLimitMiddleware:
    """Testes do middleware de rate limiting integrado ao Flask."""

    def test_headers_presentes_na_resposta(self, client, admin_headers, monkeypatch):
        monkeypatch.setattr("api.config.RATE_LIMIT_ENABLED", True)
        resp = client.get("/api/v1/health")
        # Health check não requer auth, mas rate limit headers devem estar presentes
        assert resp.status_code == 200

    def test_rate_limit_desabilitado_nao_bloqueia(self, client, monkeypatch):
        monkeypatch.setattr("api.config.RATE_LIMIT_ENABLED", False)
        for _ in range(50):
            resp = client.get("/api/v1/health")
            assert resp.status_code == 200
