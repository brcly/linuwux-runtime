# proton-LinUwUx-patch
Enables HV Bypass to work on linux.

Alone these files aren't enough to enable the patch to work.

Anyone seeing this before I finish working on it, I still need to upload a script which automates applying the patch a selectable proton version.

A user_settings.py is required for it to function.

```
user_settings = {
    "WINEDLLOVERRIDES": "winmm=n,b;version=n,b;reflex=n,b",
    "PROTON_DISABLE_LSTEAMCLIENT": "1",
}
```