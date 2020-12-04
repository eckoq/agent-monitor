#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyrigth @ 2020 , Inc

"""logging config
"""

import logging
import logging.config

_log_config = {
  "version": 1,
  "disable_existing_loggers": False,
  "formatters": {
    "simple": {
      "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
      "datefmt": "%Y-%m-%d %H:%M:%S"
    },
    "full": {
      "format": "%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s"
    }
  },
  "handlers": {
    "console": {
      "class": "logging.StreamHandler",
      "level": "DEBUG",
      "formatter": "full",
      "stream": "ext://sys.stdout"
    },
    "agent-monitor": {
      "class": "logging.handlers.TimedRotatingFileHandler",
      "level": "DEBUG",
      "formatter": "full",
      "filename": "./logs/agent.log",
      "interval": 1,
      "backupCount": 7,
      "when": "D",
      "encoding": "utf-8"
    }
  },
  "loggers": {
    "agent-monitor": {
      "level": "DEBUG",
      "handlers": [
        "agent-monitor"
      ],
      "propagate": "no"
    }
  }
}

_log_name = "agent-monitor"

logging.config.dictConfig(_log_config)

logger = logging.getLogger(_log_name)

__all__ = [
    "logger"
    ]
