# Recon runtime contract map

This map records the repository vocabulary used by the Recon knowledge datasets. Source code and strict models remain authoritative.

| Concept | Actual token/model | Source file | Visibility |
|---|---|---|---|
| Capability IDs | `dns_resolve`, `http_probe`, `nmap_scan`, `whatweb`, `http_fetch`, `browser_explore`, `browser_request`, `content_discovery`, `passive_subdomain_enum`, `passive_infra_enum`, `historical_url_discovery`, `whois_rdap_lookup`, `web_crawl`, `vhost_discovery`, `parameter_discovery`, `technology_scan`, `graphql_discovery`, `graphql_introspection`, `wsdl_discovery`, `exposure_discovery`, `sourcemap_analyze`, `external_asset_search`, `public_code_search`, `search_engine_osint` | `src/recon/models.py` | Public Recon capabilities |
| Capability policy catalog | `CapabilityDefinition`, `DEFINITIONS`, `RISK` | `src/recon/capability_catalog.py` | Runtime registry |
| Evidence | `EvidenceManifest`, `EvidenceArtifact` | `src/contracts/evidence.py`, `src/recon/models.py` | Run-specific |
| Technology evidence | `TechnologyObservation` | `src/recon/models.py` | Run-specific |
| Discovered asset | `DiscoveredAsset` | `src/contracts/recon_assets.py` | Run-specific |
| Attack surface output | `AttackSurfaceInventory`, `AttackSurfaceEntry`, `Observation`, `EndpointStatus` | `src/contracts/attack_surface.py` | Supervisor handoff |
| Planning route/service | `PlanningRoute`, `PlanningService` | `src/contracts/recon_planning.py` | Run planning |
| Coverage | `ReconCoverage` plus checklist item states | `src/recon/web_models.py`, `src/recon/checklist_v3.py` | Run-specific |
| Risk | `R0`, `R1`, `R2`, `R3`, `R4` | `src/contracts/execution.py` | Shared policy contract |
| Vector record | `VectorKnowledgeRecord` | `src/contracts/recon_kb.py` | Operator-maintained global KB |
| Lookup record | `LookupRecord` | `src/contracts/recon_kb.py` | Operator-maintained global KB |
| Runner data | `RunnerDataManifest`, registered `runner_data_id` | `src/contracts/recon_kb.py`, `src/recon/kb/runner.py` | Gateway-resolved runner input |
| RAG query | `ReconKnowledgeQuery` | `src/recon/rag/models.py` | Bounded runtime query |
| RAG retriever | `SnapshotKnowledgeRetriever` | `src/recon/rag/snapshot_retriever.py` | Promoted VECTOR_RAG only |
| Dataset manifest | `SourceManifest` | `src/contracts/recon_kb.py` | Immutable provenance and status |

The repository does not define the prompt's six-value `RunStatus` as a Recon enum. It uses task state and `ToolRunState` contracts in `src/recon/execution.py`; this task did not rename or modify those lifecycle semantics.
