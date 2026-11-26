// PM2 config for the mainnet watcher + clone-scout. Run from the mainnet clone's folder:
//   pm2 start ecosystem.mainnet.config.js && pm2 save
// Uses absolute paths so PM2 never runs the wrong copy (lesson from the Sepolia setup).
const path = require("path");
const dir = __dirname;
module.exports = {
  apps: [
    { name: "aegis-mainnet-watcher", script: path.join(dir, "watcher.js"), cwd: dir, max_restarts: 50, restart_delay: 10000 },
    { name: "aegis-mainnet-scout", script: path.join(dir, "clone-scout.js"), cwd: dir, max_restarts: 50, restart_delay: 10000 },
  ],
};
