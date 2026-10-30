"""Orquestrador de ambientes: sobe e derruba containers Docker por participante."""
import os, socket, subprocess

BASE = os.path.dirname(os.path.abspath(__file__))
NETWORK = "cti-lab-net"
LABEL = "cti-lab=1"
IMAGE_DIRS = {"cti-lab/web-01": os.path.join(BASE, "challenges", "web-01")}


class DockerError(Exception):
    pass


def _docker(*args, timeout=60):
    try:
        r = subprocess.run(["docker", *args], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
    except FileNotFoundError:
        raise DockerError("Docker não encontrado. Instale o Docker Desktop e deixe-o aberto.")
    except subprocess.TimeoutExpired:
        raise DockerError("O Docker demorou demais para responder.")
    if r.returncode != 0:
        raise DockerError((r.stderr or r.stdout).strip()[-300:] or "Erro desconhecido no Docker.")
    return r.stdout.strip()


def ensure_network():
    """Rede própria; enable_icc=false impede que um container converse com outro."""
    try:
        _docker("network", "inspect", NETWORK)
    except DockerError:
        _docker("network", "create", "--driver", "bridge",
                "-o", "com.docker.network.bridge.enable_icc=false", NETWORK)


def ensure_image(image):
    try:
        _docker("image", "inspect", image)
    except DockerError:
        if image not in IMAGE_DIRS:
            raise DockerError(f"Imagem desconhecida: {image}")
        _docker("build", "-t", image, IMAGE_DIRS[image], timeout=600)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start(name, image, container_port, flag):
    """Sobe um container isolado com a flag única do participante e devolve a porta local."""
    ensure_network()
    ensure_image(image)
    port = _free_port()
    _docker("run", "-d", "--rm", "--name", name, "--label", LABEL, "--network", NETWORK,
            "-p", f"127.0.0.1:{port}:{container_port}",   # só acessível na própria máquina
            "-e", f"FLAG={flag}",
            "--memory", "128m", "--cpus", "0.5", "--pids-limit", "100",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", "/tmp", image)
    return port


def stop(name):
    try:
        _docker("rm", "-f", name)
    except DockerError:
        pass


def cleanup_all():
    """Remove containers do laboratório que sobraram de execuções anteriores."""
    ids = _docker("ps", "-aq", "--filter", f"label={LABEL}").split()
    for i in ids:
        stop(i)
