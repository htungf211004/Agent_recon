"""Exercise the full Recon path against a real local HTTP listener."""

from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from src.recon.bootstrap import create_recon_agent
from src.recon.models import Capability, ReconTask, Scope


class LocalHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

    def log_message(self, format, *args):
        pass


def test_recon_agent_http_probe_localhost_e2e(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    while server.server_address[1] in {443, 8443, 9443}:
        server.server_close()
        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        repository, agent = create_recon_agent(tmp_path / "recon.db", tmp_path / "evidence")
        task = ReconTask(
            id="local-http", run_id="local-run",
            scope=Scope(
                allowed_ips=("127.0.0.1",),
                allowed_ports=(port,),
                capabilities=(Capability.HTTP_PROBE,),
            ),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        repository.save_task(task)
        result = agent.run(task.id)
        assert len(result.tool_results) == 1
        assert result.tool_results[0].status == "success"
        assert len(result.evidence_ids) == 1
        artifact = repository.get_evidence(result.evidence_ids[0])
        assert artifact is not None
        assert artifact.request_id == result.tool_results[0].request_id
        assert (tmp_path / "evidence" / artifact.relative_path).read_bytes().startswith(b"HTTP 200")
        decision = repository.get_policy_decision(artifact.request_id)
        assert decision is not None and decision.allowed is True
        assert repository.get_recon_result(task.id) == result
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
