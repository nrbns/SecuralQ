# SecuraIQ `agent_lib` (Phase 1)

Light modularization scaffold only.

- **Keep** the monolith entrypoint `scripts/securaiq_agent.py` for packaging
  (`build_agent_packages.py`, installers, PyInstaller).
- **Do not** split the whole agent into packages in Phase 1 unless a move is
  trivial and packaging still embeds / runs the same entry script.
- Future modules (`core` / `inventory` / `security` / `response`) can grow
  here while the entrypoint imports them gradually.

See `docs/agent-platform.md`.
