const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');

const JWT_SECRET = process.env.JWT_SECRET || 'sua_chave_secreta_super_segura';
const LOG_FILE_PATH = './bad_login.log';

app.post('/login', async function (req, res, next) {
  const { username, password } = req.body;

  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  const ip_time = new Date();

  try {
    authenticate(username, password, async function (err, user) {
      if (err) return next(err);

      let log_data = '';
      try {
        log_data = await fs.readFile(LOG_FILE_PATH, 'utf8');
      } catch (fileErr) {
        if (fileErr.code !== 'ENOENT') return next(fileErr);
      }

      const bld = log_data.split(\('\r\\)n').filter(linha => linha.trim() !== '');
      let ip_not_ban = true;
      let user_not_ban = true;

      bld.forEach(function (linha) {
        if (linha.includes(ip)) {
          const chk_ban = linha.split('@');
          if (chk_ban[4] === 'ban') {
            ip_not_ban = false;
            eventLog(`ip banned - ${username} ip:${ip} - ${ip_time}\r\n`);
          }
        }
      });

      if (ip_not_ban) {
        bld.forEach(function (linha) {
          if (linha.includes(username)) {
            const chk_u_ban = linha.split('@');
            if (chk_u_ban[4] === 'ban') {
              user_not_ban = false;
              eventLog(`user banned - ${username} ip:${ip} - ${ip_time}\r\n`);
            }
          }
        });
      }

      if (!ip_not_ban || !user_not_ban) {
        return res.status(403).json({ 
          error: 'Access denied. Account or IP is temporarily banned.' 
        });
      }

      if (user) {
        eventLog(`login ok - ${username} ip:${ip} - ${ip_time}`);

        const token = jwt.sign(
          { 
            uid: user.uid, 
            username: username,
            dir: `D_${user.uid}`
          }, 
          JWT_SECRET, 
          { expiresIn: '2h' }
        );

        let outData = '';
        bld.forEach(function (linha) {
          const dtl = linha.split('@');
          if (dtl[0] === ip && dtl[4] !== 'ban') {
            if (parseInt(new Date(ip_time) - new Date(dtl[1])) < 86400000) {
              eventLog(`User bad login cleared - ${username} ip:${ip} - ${ip_time}\r\n`);
              return;
            }
          }
          outData += linha \(+ '\r\\)n';
        });

        await fs.writeFile(LOG_FILE_PATH, outData, 'utf8');

        return res.status(200).json({
          message: 'Welcome to Main menu.',
          token: token,
          user: {
            uid: user.uid,
            username: username
          }
        });

      } else {
        let new_ip = true;
        let log_new_data = '';
        let errorMessage = 'Authentication failed.';
        let remainingAttempts = 2;

        bld.forEach(function (linha) {
          const dtl = linha.split('@');
          if (dtl[0] === ip) {
            if (dtl[4] !== 'ban') {
              if (parseInt(new Date(ip_time) - new Date(dtl[1])) < 86400000) {
                if (parseInt(dtl[2]) > 1) {
                  dtl[2] = parseInt(dtl[2]) + 1;
                  dtl[4] = 'ban';
                  errorMessage = 'Authentication failed, please reset your password.';
                  remainingAttempts = 0;
                } else {
                  dtl[2] = parseInt(dtl[2]) + 1;
                  remainingAttempts = 3 - dtl[2];
                  errorMessage = `Authentication failed, you have ${remainingAttempts} attempts left.`;
                }
              } else {
                errorMessage = 'Authentication failed, you have 2 attempts left.';
                dtl[2] = 1;
                dtl[4] = 'nok';
                remainingAttempts = 2;
              }
              log_new_data += `${ip}@${ip_time}@${dtl[2]}@${username}@${dtl[4]}\r\n`;
              new_ip = false;
            } else {
              errorMessage = 'Authentication failed, please contact administration.';
              new_ip = false;
              remainingAttempts = 0;
              log_new_data += `${dtl[0]}@${ip_time}@${dtl[2]}@${username}@${dtl[4]}\r\n`;
            }
          } else {
            if (user_not_ban) {
              log_new_data += linha \(+ '\r\\)n';
            } else {
              log_new_data += `${ip}@${ip_time}@3@${username}@ban\r\n`;
            }
          }
        });

        if (new_ip) {
          log_new_data += `${ip}@${ip_time}@1@${username}@nok\r\n`;
          errorMessage = 'Authentication failed, you have 2 attempts left.';
        }

        await fs.writeFile(LOG_FILE_PATH, log_new_data, 'utf8');

        return res.status(401).json({ 
          error: errorMessage,
          remainingAttempts: remainingAttempts
        });
      }
    });
  } catch (error) {
    return next(error);
  }
});

