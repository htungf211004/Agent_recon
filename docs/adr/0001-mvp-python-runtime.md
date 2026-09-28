# ADR 0001: MVP runtime is Python 3.11

Status: accepted for Day 02. This supersedes the early implementation-plan reference to Python 3.12.

The repository, CI workflow and Docker image already run Python 3.11. Keeping that single version avoids an untested runtime change while closing the Recon contracts. Changes to Python version require updating all three environments and running the complete test suite in the new image.

Scope: AgentRecon and the current MVP runtime. This decision does not alter the technical guidebook supplied by the program.
