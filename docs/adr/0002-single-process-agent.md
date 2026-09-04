# Run the v1 Agent as one process

The v1 Agent runs its HTTP adapter and persistent Job scheduler in one Uvicorn worker. This keeps SQLite writes, scheduler wake-ups, and port ownership under one process; multi-worker or multi-Agent execution is rejected until an external coordinator and distributed fencing can replace these assumptions.
