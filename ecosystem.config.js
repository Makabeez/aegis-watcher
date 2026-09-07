// PM2 config — start with:  pm2 start /ABSOLUTE/PATH/ecosystem.config.js
module.exports = {
  apps: [{
    name: "aegis-watcher",
    script: "/mnt/c/github/aegis-watcher/watcher.js",   // ABSOLUTE path (avoids phantom-process issues)
    cwd: "/mnt/c/github/aegis-watcher",
    instances: 1,
    exec_mode: "fork",
    autorestart: true,
    max_restarts: 10,
    restart_delay: 30000,
    max_memory_restart: "200M",
    env: { NODE_ENV: "production" },
    out_file: "/mnt/c/github/aegis-watcher/logs/out.log",
    error_file: "/mnt/c/github/aegis-watcher/logs/err.log",
    time: true,
  }]
};
