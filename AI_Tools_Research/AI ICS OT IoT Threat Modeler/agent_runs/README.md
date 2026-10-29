# Agent runs

Run logs from the original Agent.ai `IoT_OT_ICS_ThreatModeler` agent, kept as examples of how the agent's workflow behaves on real inputs.

## Files

- `index.csv` — one row per run: run ID, agent ID and name, title, creation time, status (completed or incomplete) and log file name.
- `untitled-run--<run ID>.txt` — the log of each run (59 runs; 14 completed, 45 incomplete). Each log starts with the agent details and then records the inputs, steps and outputs of that run.

Incomplete runs stopped before the final report; they are kept because they show the intermediate steps.
