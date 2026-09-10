"""Detector package wiring — all rule detectors."""
from viperstrike.detectors.base import Detector
from viperstrike.detectors.mcp001 import ShellInvocationDetector
from viperstrike.detectors.mcp002 import UnsafeSubprocessDetector
from viperstrike.detectors.mcp003 import ArbitraryWriteDetector
from viperstrike.detectors.mcp004 import PathTraversalDetector
from viperstrike.detectors.mcp005 import SSRFDetector
from viperstrike.detectors.mcp006 import CodeExecDetector
from viperstrike.detectors.mcp007 import SecretLoggingDetector
from viperstrike.detectors.mcp008 import MissingSchemaDetector
from viperstrike.detectors.mcp009 import AuthBypassDetector
from viperstrike.detectors.mcp010 import DangerousDefaultDetector
from viperstrike.detectors.mcp011 import SQLInjectionDetector
from viperstrike.detectors.mcp012 import DeserializationDetector

ALL_DETECTORS = [
    ShellInvocationDetector,
    UnsafeSubprocessDetector,
    ArbitraryWriteDetector,
    PathTraversalDetector,
    SSRFDetector,
    CodeExecDetector,
    SecretLoggingDetector,
    MissingSchemaDetector,
    AuthBypassDetector,
    DangerousDefaultDetector,
    SQLInjectionDetector,
    DeserializationDetector,
]

__all__ = ["ALL_DETECTORS", "Detector"]