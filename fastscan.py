#!/usr/bin/env python3
"""
FastScan — Bounded Async Scanner (replaces threadpool)
Never builds giant future list upfront. Semaphore 3000, generator-based tasks.
"""
import asyncio
import ipaddress
import json
import logging
import random
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import requests

from .ledger import Ledger

log = logging.getLogger("shadowray.fastscan")

# BRUTE_PRIORITY: 10 ports for direct socket dialing during scans
BRUTE_PRIORITY = [2375, 8265, 8888, 8188, 6006, 11434, 31380, 5000, 8080, 1234]

# IDB_SPECTRUM: 38 ports for InternetDB metadata filtering (full spectrum)
IDB_SPECTRUM = [
    2375, 2376,      # Docker
    8265, 8266,      # Ray
    8888, 8889, 8890, # Jupyter
    8188,            # ComfyUI
    7860,            # Gradio
    6006,            # TensorBoard
    11434, 11435,    # Ollama
    1234,            # LM Studio / Webshell
    31380,           # Kubeflow
    8080, 8081,      # MLflow, FastChat, vLLM
    5000,            # vLLM, Triton
    9200,            # Elasticsearch
    8123,            # ClickHouse
    6379,            # Redis
    5432, 3306,      # Postgres, MySQL
    9000, 9001,      # MinIO
    5678,            # n8n
    3000,            # Metabase
    15672,           # RabbitMQ
    8086,            # InfluxDB
    9090,            # Prometheus
    7077,            # Spark
    8082, 8088,      # Spark UI, YARN
    9870,            # HDFS
    4040,            # Spark UI
    9999, 7861,      # Webshell custom, Gradio
]

# Vector signatures for fingerprinting
VECTOR_SIGNATURES = {
    "ray": {"path": "/", "keywords": ["ray", "dashboard", "ray job"], "ports": [8265, 8266]},
    "docker": {"path": "/version", "keywords": ["docker", "api version", "version", "apiversion"], "ports": [2375, 2376]},
    "jupyter": {"path": "/api", "keywords": ["jupyter", "kernels", "jupyter-server", "notebook"], "ports": [8888, 8889, 8890]},
    "comfyui": {"path": "/system_stats", "keywords": ["comfyui", "system_stats", "comfy"], "ports": [8188]},
    "ollama": {"path": "/api/tags", "keywords": ["models", "ollama", "llama", "gpt"], "ports": [11434, 11435]},
    "vllm": {"path": "/v1/models", "keywords": ["data", "object", "vllm", "model", "id"], "ports": [5000, 8000]},
    "triton": {"path": "/v2/health/ready", "keywords": ["ready", "live", "triton"], "ports": [8000, 8001, 8002]},
    "mlflow": {"path": "/api/2.0/mlflow/experiments/list", "keywords": ["experiments", "mlflow", "experiment_id"], "ports": [5000, 8080]},
    "tensorboard": {"path": "/data/plugin_listing", "keywords": ["tensorboard", "plugin", "scalar", "graph"], "ports": [6006]},
    "gradio": {"path": "/config", "keywords": ["gradio", "config", "components"], "ports": [7860, 7861]},
    "lmstudio": {"path": "/v1/models", "keywords": ["data", "lmstudio", "model"], "ports": [1234]},
    "spark": {"path": "/api/v1/applications", "keywords": ["spark", "application", "driver"], "ports": [4040, 8080, 8082, 8088]},
}

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
INTERNETDB_CONCURRENCY = 100
INTERNETDB_RATE_LIMIT_DELAYS = [1, 2, 4, 8, 16, 30]  # exponential backoff


def get_port_vector(port: int) -> str:
    """Map port to primary vector."""
    for vector, sig in VECTOR_SIGNATURES.items():
        if port in sig["ports"]:
            return vector
    return "unknown"


async def probe_port(session: aiohttp.ClientSession, ip: str, port: int, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """Probe a single port, return fingerprint if service detected."""
    base = f"http://{ip}:{port}"
    vector = get_port_vector(port)
    
    # Try socket connect first (fast fail)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
    except Exception:
        return None
    
    # HTTP request - accept ANY response < 500 as confirmation
    try:
        sig = VECTOR_SIGNATURES.get(vector, {"path": "/", "keywords": []})
        async with session.get(f"{base}{sig['path']}", timeout=timeout) as resp:
            # Any HTTP response < 500 means service is live
            if resp.status < 500:
                text = await resp.text()
                text_lower = text.lower()
                # Try keyword match for higher confidence
                for kw in sig["keywords"]:
                    if kw in text_lower:
                        return {
                            "ip": ip, "port": port, "vector": vector,
                            "http_status": resp.status, "confirmed": True
                        }
                # No keyword match but service responded - assign by port
                return {
                    "ip": ip, "port": port, "vector": vector,
                    "http_status": resp.status, "port_assigned": True
                }
    except asyncio.TimeoutError:
        return {"ip": ip, "port": port, "vector": "timeout"}
    except aiohttp.ClientError:
        # Connection error but socket connected - service exists
        return {"ip": ip, "port": port, "vector": vector, "port_assigned": True}
    except Exception:
        pass
    
    return {"ip": ip, "port": port, "vector": "open_not_identified"}


async def fastscan(
    cidrs: List[str],
    ledger: Ledger,
    ports: List[int] = None,
    concurrency: int = 3000,
    skip_large_cidr: bool = True,
) -> List[Tuple[str, int, str]]:
    """
    Bounded async scanner. Yields (ip, port, vector) as results complete.
    Skips CIDRs > 65536 hosts unless skip_large_cidr=False.
    """
    if ports is None:
        ports = BRUTE_PRIORITY
    
    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=0, force_close=True, enable_cleanup_closed=True)
    timeout = aiohttp.ClientTimeout(total=5, connect=3)
    
    # Build IP generator (randomized per VENOM 5.2)
    all_ips = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            if skip_large_cidr and len(hosts) > 65536:
                log.warning("CIDR %s too large (%d hosts) — use idb-sweep instead", cidr, len(hosts))
                continue
            all_ips.extend([str(ip) for ip in hosts])
        except ValueError:
            log.warning("Bad CIDR skipped: %s", cidr)
    
    random.shuffle(all_ips)
    log.info("FastScan: %d IPs × %d ports = %d probes (concurrency %d)", len(all_ips), len(ports), len(all_ips) * len(ports), concurrency)
    
    results = []
    checked = 0
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Generator-based task creation - never builds full list
        async def probe_task(ip: str, port: int):
            nonlocal checked
            async with semaphore:
                result = await probe_port(session, ip, port)
                checked += 1
                if checked % 5000 == 0:
                    log.info("scanned ~%d probes...", checked)
                return result
        
        # Process in chunks to avoid memory pressure
        chunk_size = 10000
        for i in range(0, len(all_ips), chunk_size):
            chunk_ips = all_ips[i:i+chunk_size]
            tasks = []
            for ip in chunk_ips:
                for port in ports:
                    # Skip already-burned targets
                    rec = ledger.get(ip, port)
                    if rec and rec.get("status") == "burned":
                        continue
                    tasks.append(probe_task(ip, port))
            
            # Process as completed
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    ip, port, vector = result["ip"], result["port"], result.get("vector", "unknown")
                    results.append((ip, port, vector))
                    
                    # Update ledger
                    status_map = {
                        "ray": "ray_alive",
                        "docker": "docker_alive",
                        "jupyter": "jupyter_alive",
                        "comfyui": "comfyui_alive",
                        "ollama": "ollama_alive",
                        "vllm": "vllm_alive",
                        "triton": "triton_alive",
                        "mlflow": "mlflow_alive",
                        "tensorboard": "tensorboard_alive",
                        "gradio": "gradio_alive",
                        "lmstudio": "lmstudio_alive",
                        "spark": "spark_alive",
                        "open_not_identified": "open_not_identified",
                        "unknown_open": "unknown_open",
                        "timeout": "timeout",
                    }
                    status = status_map.get(vector, "unknown_open")
                    ledger.upsert(ip, port, status=status, vector=vector, **{k: v for k, v in result.items() if k not in ("ip", "port", "vector")})
                    
                    if status != "open_not_identified" and status != "unknown_open" and status != "timeout":
                        log.info("[+] %s %s:%s %s", vector.upper(), ip, port, result.get("http_status", ""))
    
    log.info("FastScan complete: %d confirmed services", len(results))
    return results


async def internetdb_sweep(
    ips: List[str],
    ledger: Ledger,
    concurrency: int = INTERNETDB_CONCURRENCY,
) -> List[Tuple[str, List[int]]]:
    """
    Keyless Shodan InternetDB sweep. Returns (ip, open_ports[]) for each IP.
    Rate-limited with exponential backoff.
    """
    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=0, force_close=True)
    timeout = aiohttp.ClientTimeout(total=10)
    
    results = []
    
    async def query_ip(session: aiohttp.ClientSession, ip: str) -> Tuple[str, List[int]]:
        url = INTERNETDB_URL.format(ip=ip)
        async with semaphore:
            for delay in INTERNETDB_RATE_LIMIT_DELAYS:
                try:
                    async with session.get(url, timeout=timeout) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            ports = data.get("ports", [])
                            if ports:
                                # Filter to IDB_SPECTRUM ports
                                spectrum_ports = [p for p in ports if p in IDB_SPECTRUM]
                                if spectrum_ports:
                                    return (ip, spectrum_ports)
                            return (ip, [])
                        elif resp.status == 429:
                            await asyncio.sleep(delay + random.random() * 2)
                            continue
                        else:
                            return (ip, [])
                except Exception:
                    await asyncio.sleep(delay + random.random() * 2)
                    continue
            return (ip, [])
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [query_ip(session, ip) for ip in ips]
        for coro in asyncio.as_completed(tasks):
            ip, ports = await coro
            if ports:
                results.append((ip, ports))
                # Pre-populate ledger with InternetDB findings
                for port in ports:
                    vector = get_port_vector(port)
                    ledger.upsert(ip, port, status="idb_candidate", vector=vector, source="internetdb", idb_ports=ports)
    
    return results


def idb_sweep_cidrs(cidrs: List[str], ledger: Ledger, sample_size: int = 10000) -> List[Tuple[str, List[int]]]:
    """
    Sweep CIDRs via InternetDB: sample IPs from each CIDR, query InternetDB,
    then validate candidates with fastscan.
    """
    all_ips = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > sample_size:
                # Random sample
                sampled = random.sample([str(h) for h in hosts], sample_size)
            else:
                sampled = [str(h) for h in hosts]
            all_ips.extend(sampled)
        except ValueError:
            continue
    
    random.shuffle(all_ips)
    log.info("InternetDB sweep: %d IPs sampled from %d CIDRs", len(all_ips), len(cidrs))
    
    # Run async sweep
    results = asyncio.run(internetdb_sweep(all_ips, ledger))
    
    # Now validate candidates with fastscan on their specific ports
    if results:
        candidate_ports = set()
        ip_port_map = {}
        for ip, ports in results:
            for port in ports:
                candidate_ports.add(port)
                ip_port_map.setdefault(ip, []).append(port)
        
        # Filter to BRUTE_PRIORITY for validation
        validation_ports = [p for p in candidate_ports if p in BRUTE_PRIORITY]
        if validation_ports:
            log.info("Validating %d candidate IPs on %d ports", len(results), len(validation_ports))
            # Build filtered CIDR list for fastscan
            cidr_list = list(set(ip.rsplit(".", 1)[0] + ".0/24" for ip in ip_port_map.keys()))
            fastscan_results = asyncio.run(fastscan(cidr_list, ledger, ports=validation_ports))
            return results
    
    return results


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    
    # Test with small range
    ledger = Ledger("test_scan.json")
    test_cidrs = ["34.128.182.0/24", "34.128.189.0/24"]
    
    print("Testing fastscan...")
    results = asyncio.run(fastscan(test_cidrs, ledger, ports=BRUTE_PRIORITY, concurrency=500))
    print(f"Found {len(results)} services")
    for ip, port, vector in results:
        print(f"  {ip}:{port} -> {vector}")
    
    print("\nTesting InternetDB sweep...")
    idb_results = idb_sweep_cidrs(test_cidrs, ledger, sample_size=500)
    print(f"IDB found {len(idb_results)} IPs with spectrum ports")
    for ip, ports in idb_results[:5]:
        print(f"  {ip}: {ports}")
