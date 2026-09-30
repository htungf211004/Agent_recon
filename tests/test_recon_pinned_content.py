import json

import httpx

from src.recon.models import Capability, ContentDiscoveryParams
from src.recon.pinned_content import PinnedContentDiscoveryAdapter
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.scope.admission import admit_target
from src.recon.storage import ReconRepository


def test_domain_content_discovery_keeps_pinned_transport_and_host(tmp_path):
    observed = []
    def respond(request):
        observed.append((request.url.host, request.headers["host"], request.method))
        return httpx.Response(200 if request.url.path.endswith("robots.txt") else 404)
    task, boundary = admit_target("example.test", "content", pinned_addresses=("127.0.0.1",))
    repository = ReconRepository(tmp_path / "db.sqlite")
    repository.save_task(task)
    repository.save_authorization(boundary)
    request = ReconPlanner._action(task, "127.0.0.1", Capability.CONTENT_DISCOVERY,
                                   ContentDiscoveryParams(port=443, scheme="https", path_prefix="/",
                                                          wordlist_id="web-common-small-v1")).request
    assert PolicyService(repository).decide(request).allowed
    output = PinnedContentDiscoveryAdapter(httpx.MockTransport(respond)).execute(request)
    assert output.status == "success"
    assert all(row == ("127.0.0.1", "example.test:443", "HEAD") for row in observed), observed
    assert json.loads(output.raw_output)["candidates"] == [
        {"url": "https://example.test:443/robots.txt", "status_code": 200}]
