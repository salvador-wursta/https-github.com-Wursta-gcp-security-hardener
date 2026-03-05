"""
Middleware package for the application
"""
from .csrf_middleware import CSRFMiddleware

__all__ = ["CSRFMiddleware"]
