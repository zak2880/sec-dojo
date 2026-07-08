# WMI Persistence

- [ ] Read
- [ ] Reviewed KQL example
- [ ] Could explain this to someone else

## Why this matters for detection

WMI persistence leaves no obvious autorun entry, no Task Scheduler GUI item, and no Run-key value — analysts sweeping the "usual suspects" walk right past it.

## Core concept

- A WMI event subscription has **three parts**, all stored in the WMI repository rather than the registry or an on-disk file most people think to check: an **Event Filter** (the trigger condition, e.g. "every 5 minutes" or "on user logon"), an **Event Consumer** (the action to take), and a **Filter-to-Consumer Binding** that ties the two together.
- The most abused consumer type is `CommandLineEventConsumer`, which executes a command directly when the filter fires — functionally equivalent to a scheduled task, but far less commonly audited.
- **Why it's stealthier:** it executes via `WmiPrvSe.exe`, itself a completely legitimate Windows host process, so process-tree review shows nothing more alarming than "WMI provider host ran something" unless you specifically inspect *what*.
- **What does catch it:** MDE natively records WMI persistence artefact creation as the repository objects are written — filter creation, consumer creation, and the binding between them are each individually logged, giving three separate chances to catch it going in, before it ever fires.

## Diagram

```
Event Filter:    "every 300 seconds"
Event Consumer:  CommandLineEventConsumer → powershell.exe -enc ...
Binding:         Filter ──bound to──▶ Consumer
                                          │
                                          ▼
                       Fires silently, forever, via WmiPrvSe.exe
```

## KQL Example

**Variant A — any filter-to-consumer binding created (broad):**

```kql
DeviceEvents
| where ActionType == "WmiBindEventFilterToConsumer"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, AdditionalFields
| sort by Timestamp desc
```

**Variant B — tuned to the most abused consumer type (CommandLineEventConsumer):**

Most legitimate WMI subscriptions (monitoring/management tooling) use less code-executing consumer types. Narrow to the one that actually runs a command:

```kql
DeviceEvents
| where ActionType in ("WmiCreateEventConsumer", "WmiBindEventFilterToConsumer")
| where AdditionalFields has "CommandLineEventConsumer"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, AdditionalFields
| sort by Timestamp desc
```
