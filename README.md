# obslog
Implementation of a Syslog server in PHP that feeds directly into Observium because Observium is stupid. 

Only basic but better than nothing.

Observium does a woeful job of matching hostnames, this works around that slightly.

Ensure the `require_once()` is pointing to your Observium config.php to get MySQL details. Only supports MySQL currently. Add to the `$filters` array to include more regex to filter the log entries.

Run this in `supervisord` using a config like below:

```
[program:obslog]
command=/opt/obslog/obslog.php
autostart=true
autorestart=unexpected
```
