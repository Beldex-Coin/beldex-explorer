import flask
from datetime import datetime, timedelta, timezone
import babel.dates
import json
import sys
import statistics
import string
import requests

class Hex64Converter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = "[0-9a-fA-F]{64}"

app.url_map.converters['hex64'] = Hex64Converter