#!/bin/bash
exec python -m uvicorn stream_handler:app --host 0.0.0.0 --port 8080
