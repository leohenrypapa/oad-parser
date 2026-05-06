"""Custom exceptions used by oad-parser."""

class OadParserError(Exception):
    """Base exception for oad_parser."""


class ParseError(OadParserError):
    """Raised when parser input cannot be parsed."""


class ValidationError(OadParserError):
    """Raised when parser output validation fails."""
