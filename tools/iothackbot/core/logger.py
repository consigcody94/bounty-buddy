"""
Logging framework for Bounty Buddy tools.
Provides centralized logging with configurable levels and formatting.

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional
from logging.handlers import RotatingFileHandler


class IoTHackBotLogger:
    """Centralized logger for IoTHackBot tools"""

    _instance: Optional[logging.Logger] = None
    _initialized: bool = False

    @classmethod
    def get_logger(
        cls,
        name: str = "iothackbot",
        level: int = logging.INFO,
        log_file: Optional[str] = None,
        console: bool = True,
        file_level: int = logging.DEBUG,
        console_level: int = logging.INFO
    ) -> logging.Logger:
        """
        Get or create a logger instance with specified configuration.

        Args:
            name: Logger name
            level: Base logging level
            log_file: Optional log file path
            console: Whether to log to console
            file_level: Log level for file handler
            console_level: Log level for console handler

        Returns:
            Configured logger instance
        """
        if cls._instance is None or not cls._initialized:
            cls._instance = logging.getLogger(name)
            cls._instance.setLevel(level)
            cls._instance.handlers.clear()

            # Create formatters
            detailed_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            simple_formatter = logging.Formatter(
                '%(levelname)s - %(message)s'
            )

            # Console handler
            if console:
                console_handler = logging.StreamHandler(sys.stdout)
                console_handler.setLevel(console_level)
                console_handler.setFormatter(simple_formatter)
                cls._instance.addHandler(console_handler)

            # File handler
            if log_file:
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)

                file_handler = RotatingFileHandler(
                    log_file,
                    maxBytes=10 * 1024 * 1024,  # 10MB
                    backupCount=5
                )
                file_handler.setLevel(file_level)
                file_handler.setFormatter(detailed_formatter)
                cls._instance.addHandler(file_handler)

            cls._initialized = True

        return cls._instance

    @classmethod
    def reset(cls):
        """Reset logger instance (useful for testing)"""
        if cls._instance:
            cls._instance.handlers.clear()
        cls._instance = None
        cls._initialized = False


def setup_tool_logger(
    tool_name: str,
    verbose: bool = False,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Setup logger for a specific tool with common configuration.

    Args:
        tool_name: Name of the tool (used as logger name)
        verbose: Enable verbose logging (DEBUG level)
        log_file: Optional log file path

    Returns:
        Configured logger for the tool
    """
    level = logging.DEBUG if verbose else logging.INFO
    console_level = logging.DEBUG if verbose else logging.INFO

    return IoTHackBotLogger.get_logger(
        name=f"iothackbot.{tool_name}",
        level=level,
        log_file=log_file,
        console=True,
        console_level=console_level
    )


# Convenience functions
def debug(msg: str, *args, **kwargs):
    """Log debug message"""
    IoTHackBotLogger.get_logger().debug(msg, *args, **kwargs)


def info(msg: str, *args, **kwargs):
    """Log info message"""
    IoTHackBotLogger.get_logger().info(msg, *args, **kwargs)


def warning(msg: str, *args, **kwargs):
    """Log warning message"""
    IoTHackBotLogger.get_logger().warning(msg, *args, **kwargs)


def error(msg: str, *args, **kwargs):
    """Log error message"""
    IoTHackBotLogger.get_logger().error(msg, *args, **kwargs)


def critical(msg: str, *args, **kwargs):
    """Log critical message"""
    IoTHackBotLogger.get_logger().critical(msg, *args, **kwargs)
