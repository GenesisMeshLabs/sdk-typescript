### Changed

Refused before anything runs, as the .NET SDK refuses them (T2 of the parity plan):

- **`cancelByRotatingForward`:** a rotation whose action is other than `rotate` or `update`, or which names another resource than the remediation's (the resource was replaced silently).
- **`urgentAction`:** an empty emergency capability, or no emergency policies, before anything is evaluated.
