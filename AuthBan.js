app.post('/login', function (req, res, next) {
  authenticate(req.body.username, req.body.password, function(err, user){
    if (err) return next(err);
    var ip=req.headers.origin['x-forwarded-for'] || req.socket.remoteAddress || null;
    var ip_time=new Date();
    const log_data=fs.readFileSync('./bad_login.log','utf8');
    var bld=log_data.split('\r\n');
    var ip_not_ban=true;
    var user_not_ban=true;
    bld.forEach(function(linha){
		if (linha.includes(ip)){
			var chk_ban=linha.split('@');
			if (chk_ban[4]=='ban'){
				ip_not_ban=false;
				eventLog('ip banned - '+req.body.username+' ip:'+ip+' - '+ip_time+'\r\n');
			}
		}
	});
	if (ip_not_ban){
		bld.forEach(function(linha2){
			if (linha2.includes(req.body.username)){
				var chk_u_ban=linha2.split('@');
				if (chk_u_ban[4]=='ban'){
					user_not_ban=false;
					eventLog('user banned - '+req.body.username+' ip:'+ip+' - '+ip_time+'\r\n');
				}
			}
		});
	}
	if (ip_not_ban & user_not_ban){
		if (user) {
			req.session.regenerate(function(){
				eventLog('login ok - '+req.body.username+'  ip:'+ip+' - '+ip_time);
				req.session.user = user;
				//var n=users.findIndex(elem => (elem.name==req.session.user.name));
				req.session.dir='D_'+user.uid;//users[n].uid;
				const dados_path=require.resolve('./pblc/'+req.session.dir+'/dados.js');
				delete require.cache[dados_path];
				var dados=require('./pblc/'+req.session.dir+'/dados.js');
				req.session.msgum='Welcome to Main menu.';
				req.session.Num=0;
				req.session.dnl_bool=false;
				req.session.dnl_ini=new Date();
				req.session.msgmm='';
				req.session.prelist='';
				res.redirect('/usermenu');
				var outData='';
				bld.forEach(function(linha){
					if (linha!='\r\n' & linha!=''){
						var dtl = linha.split('@');
						if (dtl[0]==ip){
							if (dtl[4]!='ban'){
								if (parseInt(new Date(ip_time)-new Date(dtl[1]))<86400000){
									linha=null;
									eventLog('User bad login cleared - '+req.body.username+' ip:'+ip+' - '+ip_time+'\r\n');
								}
							}
						}
					}
					if (linha!=null)outData+=linha +'\r\n';
				});
				fs.writeFile('./bad_login.log', outData, err => {if (err) {console.error(err)}});	
			});
		} else {
			var new_ip=true;
			var log_new_data='';
			bld.forEach(function(linha){
				if (linha!='\r\n' & linha!=''){
					var dtl = linha.split('@');
					if (dtl[0]==ip){
						if (dtl[4]!='ban'){
							if (parseInt(new Date(ip_time)-new Date(dtl[1]))<86400000){
								if (parseInt(dtl[2])>1){
									dtl[2]=parseInt(dtl[2])+1;
									dtl[4]='ban';
									req.session.error = 'Authentication failed, please reset your password.';
								}else{
									dtl[2]=parseInt(dtl[2])+1;
									var qt=3-dtl[2];
									req.session.error = 'Authentication failed, you have '+qt+' atempt left. ';
								}
							}else{
								req.session.error = 'Authentication failed, you have 2 atempts left.';
								dtl[2]=1;
								dtl[4]='nok';
							}
							log_new_data+=ip+'@'+ip_time+'@'+dtl[2]+'@'+req.body.username+'@'+dtl[4]+'\r\n';
							new_ip=false;
						}else{
							req.session.error = 'Authentication failed, please contact administration.';
							new_ip=false;
							log_new_data+=dtl[0]+'@'+ip_time+'@'+dtl[2]+'@'+req.body.username+'@'+dtl[4]+'\r\n';
						}
					}else{
						if (user_not_ban){
							log_new_data+=linha+'\r\n';
						}else{
							log_new_data+=ip+'@'+ip_time+'@3@'+req.body.username+'@ban\r\n';
						}
					}
				}
			});
			if (new_ip){
				log_new_data+=ip+'@'+ip_time+'@1@'+req.body.username+'@nok'+'\r\n';
				req.session.error = 'Authentication failed, you have 2 atempts left.';
			}
			fs.writeFile('./bad_login.log', log_new_data, err => {if (err) {console.error(err)}});
			res.redirect('/login');
		}
	}else{
		res.redirect('/badlog');
	}
  });
});
