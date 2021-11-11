const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASEINVITE = "BCDEFGHJKLMNPQRSTUVWXYZ";
const SECRET = "secret";
const FREEINVITECOUNT = 1;

const crypto = require("crypto");
const http = require("http");
const https = require("https");
const tls = require("tls");
const fs = require("fs");
const bodyParser = require("body-parser");
const cors = require("cors");
const express = require("express");
const session = require("express-session");
const hcaptcha = require("express-hcaptcha");
var xss = require("xss");
var Mailjet = require("node-mailjet").connect("myinfo", "myinfo");
const mongoSanitize = require("express-mongo-sanitize");
var cookieParser = require("cookie-parser");
var vhost = require("vhost");
var multer = require("multer");
const { exit } = require("process");
const bs58 = require("base-x")(BASE58);
const bsInv = require("base-x")(BASEINVITE);
const rateLimiter = require("./rateLimiter");
var mongoUtil = require("./mongoUtil");
var app = express();
var mainResp = express();
var httpVer = express();
const config = require("./config.json");
const { escapeXML } = require("ejs");

const storage = multer.diskStorage({
	destination: (req, file, cb) => {
		cb(null, "uploads");
	},
	filename: (req, file, cb) => {
		var newName = bs58.encode(crypto.randomBytes(13));
		var prefix = "p";
		var extension;
		switch (file.mimetype) {
			case "text/plain":
				prefix = "t";
				extension = "text";
				break;
			case "image/png":
				extension = "png";
				break;
			case "image/gif":
				extension = "gif";
				break;
			case "image/jpeg":
			default:
				extension = "jpg";
				break;
		}
		req.body.newfilename = prefix + newName + "000." + extension;
		cb(null, req.body.newfilename);
	},
});
const fileFilter = (req, file, cb) => {
	if (
		file.mimetype == "text/plain" ||
		file.mimetype == "image/jpeg" ||
		file.mimetype == "image/png" ||
		file.mimetype == "image/gif"
	) {
		cb(null, true);
	} else {
		cb(null, false);
	}
};
const upload = multer({ storage: storage, fileFilter: fileFilter, limits: { fileSize: 4000000 } });

mainResp.get("/*", (req, res, next) => {
	if (req.originalUrl == "/downloads/sharex") {
		if (req.session.user && req.session.user.id) {
			res.download(__dirname + "/private/" + config.domain + ".sxcu", "config.sxcu");
		} else {
			res.status(403).send("Unauthorized");
		}
	} else if (req.originalUrl && req.originalUrl != "favicon.ico") {
		var imageId = req.originalUrl.replace(/\//gm, "");
		var checkIsImage = imageId.replace(/[^a-zA-Z\d]/gm, "");
		if (checkIsImage != imageId) {
			res.send("welcome");
			return;
		}
		mongoUtil.getImageModel().findOne({ id: imageId }, (err, image) => {
			if (!image || image.size < 1 || typeof image === 'undefined' || typeof image["fileName"] === 'undefined') {
				res.send("welcome");
			} else if(image["fileName"].includes(".text")){
				mongoUtil.getUserModel().findOne({ id: image.userid }, (err, user) => {
				if (!image || image.size < 1) {
					console.error(err);
					res.send("error fetching text");
					return;
				}
				fs.readFile("/var/www/uploads/" + image["fileName"], 'utf8', (err, data) => {
					if (err) {
						console.error(err);
						res.send("error fetching text");
						return;
					}
					res.render("text.ejs", {
						text: xss(data).trim(),
						username: user.username,
					});
				});
				});
			} else {
				// send the image
				res.sendFile("/var/www/uploads/" + image["fileName"], (err) => {
					//
				});
			}
		});
	} else {
		res.send("welcome");
	}
});
mainResp.post("/api/sharex", upload.single("image"), (req, res) => {
	try {
		if (!req.body.username) {
			res.status(400).json({ error: "No username provided" });
			return;
		}
		if (!req.body.password) {
			res.status(400).json({ error: "No password provided" });
			return;
		}
		var domain = config.domain;
		if (req.body.domain && config.domains.includes(req.body.domain)) {
			domain = req.body.domain;
		}

		mongoUtil.getUserModel().findOne({ username: req.body.username }, (err, user) => {
			if (!user || user.size < 1) {
				res.status(403).json({ error: "Invalid username or password" });
				return;
			} else if (!user.verified) {
				res.status(403).json({ error: "Verify your email first" });
				return;
			} else {
				var hash = crypto.createHash("sha512");
				hash.update(req.body.password + user.salt);
				var password = bs58.encode(hash.digest());
				if (password == user.password) {
					var id = "s" + bs58.encode(crypto.randomBytes(9));
					var quickTime = new Date().toLocaleString();
					mongoUtil.getImageModel().create(
						{
							id: id,
							fileName: req.body.newfilename,
							userid: user.id,
							uploaded: quickTime,
						},
						function (err) {
							if (err) {
								res.status(500).json({ error: "Failed to update database" });
								return;
							}
							if(req.body.sub){
								var sub = req.body.sub.replace(/[^\w\d]/gm, "");
								if(sub.length > 0) {
									res.status(201).json({ success: "https://" + sub + "." + domain + "/" + id });
									return;
								}
							}
							res.status(201).json({ success: "https://" + domain + "/" + id });
							return;
						}
					);
				} else {
					res.status(403).json({ error: "Invalid username or password" });
					return;
				}
			}
		});
	} catch (error) {
		console.error(error);
	}
});

mainResp.post("/account/page", (req, res) => {
	if (req.session.user && req.session.user.id) {
		mongoUtil
			.getInviteModel()
			.find({ forUser: req.session.user.id })
			.then(function (inviteList) {
				var invites = "";

				inviteList.forEach(function (inv) {
					var currentDateTime = new Date();
					var createdDT = Date.parse(inv.created);
					var note = "";
					if ((currentDateTime - createdDT) / 86400000 < 1) {
						// Must be at least 1 day old
						note = " *";
					}
					invites = invites + '<tr><th scope="row">' + inv.invite + note + "</th></tr>";
				});

				mongoUtil
					.getImageModel()
					.find({ userid: req.session.user.id })
					.then(function (imageList) {
						var images = "";
						imageList.forEach(function (img) {
							if(img.fileName){
								var extension = img.fileName.split(".")[1];
								var isImg = "imgRow";
								if(extension == "text"){
									isImg = "";
								}
								images =
									images +
									'<tr class="'+isImg+'"><th scope="row"><a href="/' + img.id + '" target="_blank">' + img.id + " [" + extension + "] [" + img.uploaded + "]</a></th></tr>";
							}
						});

						mongoUtil
							.getUserModel()
							.find({ referredBy: req.session.user.id })
							.then(function (inviteeList) {
								var invitees = "";

								inviteeList.forEach(function (invitee) {
									invitees =
										invitees + '<tr><th scope="row">' + invitee.username + "</th></tr>";
								});

								var showVery = 'style="display:none;"';
								if (!req.session.user.verified) {
									showVery = "";
								}

								res.render("user.ejs", {
									username: req.session.user.username,
									invites: invites,
									invitees: invitees,
									images: images,
									verification: showVery,
								});
							})
							.catch(function (error) {
								res.send("Error, reload page or contact support");
							});
					})
					.catch(function (error) {
						res.send("Error, reload page or contact support");
					});
			})
			.catch(function (error) {
				res.send("Error, reload page or contact support");
			});
	} else {
		res.status(403).send("Unauthorized");
	}
});

mainResp.post("/account/register", hcaptcha.middleware.validate(SECRET), (req, res) => {
	try {
		if (!req.body.username) {
			res.status(400).json({ error: "No username provided" });
			return;
		}
		if (!req.body.email) {
			res.status(400).json({ error: "No email provided" });
			return;
		}
		if (!req.body.password) {
			res.status(400).json({ error: "No password provided" });
			return;
		}
		if (!req.body.invite) {
			res.status(400).json({ error: "No invite provided" });
			return;
		}
		if (req.body.username.length < 2) {
			res.status(400).json({ error: "Username is too short" });
			return;
		}
		if (req.body.email.indexOf("@") < 0 || req.body.email.length > 150) {
			res.status(400).json({ error: "Invalid email" });
			return;
		}
		if (req.body.password.length < 8) {
			res.status(400).json({ error: "Password is too short" });
			return;
		}
		if (req.body.username.length > 55) {
			res.status(400).json({ error: "Username is too long" });
			return;
		}
		if (req.body.password.length > 77) {
			res.status(400).json({ error: "Password is too long" });
			return;
		}
		if (req.body.invite.length < 5) {
			res.status(400).json({ error: "Invalid invite" });
			return;
		}
		if (!isAlphanumeric(req.body.username)) {
			res.status(400).json({ error: "Usernames must be alpha-numeric" });
			return;
    }

		mongoUtil.getUserModel().findOne({ username: req.body.username }, (err, user) => {
			if (user) {
				res.status(403).json({ error: "That username is taken" });
				return;
			} else {
				mongoUtil.getUserModel().findOne({ email: req.body.email }, (err, user) => {
					if (user) {
						res.status(403).json({ error: "That email is already in use" });
						return;
					}
					mongoUtil.getInviteModel().findOneAndDelete({ invite: req.body.invite }, (err, invite) => {
						if (!invite) {
							res.status(403).json({ error: "Invalid invite" });
							return;
						}
						if (invite.forUser != adminInviteUser) {
							var currentDateTime = new Date();
							var createdDT = Date.parse(invite.created);
							if ((currentDateTime - createdDT) / 86400000 < 1) {
								// Must be at least 1 day old
								res.status(403).json({
									error: "Free invites cannot be used for at least 1 day",
								});
								return;
							}
						}
						var hash = crypto.createHash("sha512");
						var salt = bs58.encode(crypto.randomBytes(6));
						var verifyCode = bs58.encode(crypto.randomBytes(12));
						hash.update(req.body.password + salt);
						var password = bs58.encode(hash.digest());
						var id = "u" + bs58.encode(crypto.randomBytes(10));

						mongoUtil.getUserModel().create(
						{
							id: id,
							invite: invite,
							referredBy: invite.forUser,
							email: req.body.email,
							username: req.body.username,
							password: password,
							salt: salt,
							verifyCode: verifyCode,
							verified: false,
							created: new Date().toLocaleString(),
						},
						function (err) {
							if (err) {
							res.status(500).json({ error: "Failed to update database" });
							return;
							}
							var sendFrom = "noreply@" + config.domain;
							var sendEmail = Mailjet.post("send", { version: "v3.1" }).request({
							Messages: [
								{
								From: {
									Email: sendFrom,
									Name: "My Site",
								},
								To: [
									{
									Email: req.body.email,
									Name: req.body.username,
									},
								],
								TemplateID: 2211911,
								TemplateLanguage: true,
								Subject: "Please verify your email",
								Variables: {
									username: req.body.username,
									code: verifyCode,
									invites: FREEINVITECOUNT,
									year: "2021",
								},
								},
							],
							}).then((result) => {
								res.status(201).json({ success: "Created new user" });
							})
							.catch((err) => {
								console.log(err.statusCode);
								res.status(500).json({ error: "Failed to send verification email, try again later or contact support" });
								res.end();
								return;
							});
						}
						);
					});
				});
			}
		});
	} catch (error) {
		console.error(error);
	}
});

mainResp.post("/account/verify", (req, res) => {
	if (req.session.user && req.session.user.id) {
		if (!req.body.code) {
			res.status(400).json({ error: "No verification code provided" });
			return;
		}
		mongoUtil.getUserModel().findOne({ username: req.session.user.username }, function (err, user) {
			if (!user || user.size < 1) {
				res.status(403).json({ error: "Please sign in" });
				return;
			}
			if (user.verified) {
				res.status(403).json({ error: "Your account is already verified" });
				return;
			}
			if (req.body.code.trim() == user.verifyCode) {
				user.verifyCode = "";
				user.verified = true;
				createInvites(null, null, FREEINVITECOUNT, user.id);
				user.save(function (err) {
					if (err) {
						res.status(400).json({ error: "Something went wrong" });
						return;
					}
					req.session.user = user; // Update immediately so subsequent requests have the latest info
					res.status(200).send(
						"Your email is verified and your invites are available.  Your invites will be active in 24 hours."
					);
					return;
				});
			} else {
				res.status(400).json({ error: "Invalid verification code" });
				return;
			}
		});
	} else {
		res.status(403).json({ error: "Please sign in" });
	}
});
mainResp.post("/account/resend", (req, res) => {
	if (req.session.user && req.session.user.id) {
		mongoUtil.getUserModel().findOne({ username: req.session.user.username }, async function (err, user) {
			if (!user || user.size < 1) {
				res.status(403).json({ error: "Please sign in" });
				return;
			}
			if (user.verified) {
				res.status(403).json({ error: "Your account is already verified" });
				return;
      }
      //
      // Prevent SPAMMING
      const resendUsername = await rateLimiter.limiterResends.get(user.username);

      let retrySecs = 0;
      // Check if Username is already blocked
      if (resendUsername !== null && resendUsername.remainingPoints < 1) {
        retrySecs = Math.round(resendUsername.msBeforeNext / 1000) || 1;
      }
      if (retrySecs > 0) {
        res.set("Retry-After", String(retrySecs));
        res.status(429).json({ error: "You can only send confirmation emails every few hours.  Try again in " + retrySecs + " seconds or contact support." });
        return;
      }
      rateLimiter.limiterResends.consume(user.username).catch((e) => {});

			var verifyCode = bs58.encode(crypto.randomBytes(12));
			user.verifyCode = verifyCode;
			var sendFrom = "noreply@" + config.domain;

			var sendEmail = Mailjet.post("send", { version: "v3.1" }).request({
				Messages: [
					{
						From: {
							Email: sendFrom,
							Name: "My Site",
						},
						To: [
							{
								Email: user.email,
								Name: user.username,
							},
						],
						TemplateID: 2211911,
						TemplateLanguage: true,
						Subject: "Please verify your email",
						Variables: {
							username: user.username,
							code: verifyCode,
							invites: FREEINVITECOUNT,
							year: "2021",
						},
					},
				],
			});
			sendEmail
				.then((result) => {
					console.log(result.body);
				})
				.catch((err) => {
					console.log(err.statusCode);
				});
			user.save(function (err) {
				if (err) {
					res.status(400).json({ error: "Something went wrong" });
					return;
				}
				req.session.user = user; // Update immediately so subsequent requests have the latest info
				res.status(200).send("Your verification email was resent.");
				return;
			});
		});
	} else {
		res.status(403).json({ error: "Please sign in" });
	}
});

const getUsernameIPkey = (username, ip) => `${username}_${ip}`;
mainResp.post("/account/login", async (req, res) => {
	try {
		if (!req.body.username) {
			res.status(400).json({ error: "No username provided" });
			return;
		}
		// Rate limiter checks
		const ipAddr = req.ip;
		const usernameIPkey = getUsernameIPkey(req.body.username, ipAddr);

		const [resUsernameAndIP, resFastByIp, resSlowByIP] = await Promise.all([
			rateLimiter.limiterConsecutiveFailsByUsernameAndIP.get(usernameIPkey),
			rateLimiter.limiterFastBruteByIP.get(ipAddr),
			rateLimiter.limiterSlowBruteByIP.get(ipAddr),
		]);

		let retrySecs = 0;
		// Check if IP or Username + IP is already blocked
		if (resSlowByIP !== null && resSlowByIP.remainingPoints < 1) {
			retrySecs = Math.round(resSlowByIP.msBeforeNext / 1000) || 1;
		} else if (resFastByIp !== null && resFastByIp.remainingPoints < 1) {
			retrySecs = Math.round(resFastByIp.msBeforeNext / 1000) || 1;
		} else if (resUsernameAndIP !== null && resUsernameAndIP.remainingPoints < 1) {
			retrySecs = Math.round(resUsernameAndIP.msBeforeNext / 1000) || 1;
		}
		if (retrySecs > 0) {
			res.set("Retry-After", String(retrySecs));
			res.status(429).json({ error: "You're going too fast, retry in " + retrySecs + " seconds." });
			return;
		}
		//
		if (!req.body.password) {
			res.status(400).json({ error: "No password provided" });
			return;
		}
		if (!isAlphanumeric(req.body.username)) {
			res.status(403).json({ error: "Invalid username or password" });
			return;
		}
		mongoUtil.getUserModel().findOne({ username: req.body.username }, (err, user) => {
			if (!user || user.size < 1) {
				rateLimiter.limiterConsecutiveFailsByUsernameAndIP.consume(usernameIPkey).catch((e) => {});
				rateLimiter.limiterFastBruteByIP.consume(ipAddr).catch((e) => {});
				rateLimiter.limiterSlowBruteByIP.consume(ipAddr).catch((e) => {});
				res.status(403).json({ error: "Invalid username or password" });
			} else {
				var hash = crypto.createHash("sha512");
				hash.update(req.body.password + user.salt);
				var password = bs58.encode(hash.digest());
				if (password == user.password) {
					req.session.user = user;
					res.send("hello");
				} else {
					res.status(403).json({ error: "Invalid username or password" });
				}
			}
		});
	} catch (error) {
		console.error(error);
	}
});
mainResp.post("/account/logout", (req, res) => {
	req.session.destroy(function (err) {
		if (err) {
			res.send("You aren't logged in");
		} else {
			res.send("Logged out");
		}
	});
});

const adminInviteUser = "!!ADMIN!!";
mainResp.post("/invites/create", (req, res) => {
	try {
		if (!req.body.password || req.body.password != "AdminPassword") {
			res.status(403).json({ error: "unauthorized" });
			return;
		}
		var total = 1;
		if (req.body.count) {
			var total = req.body.count;
		}
		var forUser = adminInviteUser;
		if (req.body.userid) {
			forUser = req.body.userid;
		}
		if (total > 200) {
			total = 200;
		}
		var result = createInvites(res, req, total, forUser);
	} catch (error) {
		console.error(error);
	}
});

httpVer.get("*", function (req, res) {
	res.redirect("https://" + req.headers.host + req.url);
});

app.use(rateLimiter.rateLimiterMiddleware);

app.use(express.static(__dirname + "/pages"));
app.engine("html", require("ejs").renderFile);
app.set("view engine", "ejs");
app.use(cookieParser());
app.use(
	session({
		name: "test.us",
		secret: "mysecret-changethis",
		resave: false,
		saveUninitialized: true,
		cookie: {
			httpOnly: true,
			secure: true,
		},
	})
);

app.use(cors());
app.use(bodyParser.json()); // required by express-hcaptcha
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(mongoSanitize()); // Prevent injection

var sites = {};
config.domains.forEach((domain) => {
	sites[domain] = {
		app: mainResp,
		context: tls.createSecureContext({
			key: fs.readFileSync("/etc/letsencrypt/live/" + domain + "/privkey.pem").toString(),
			cert: fs.readFileSync("/etc/letsencrypt/live/" + domain + "/fullchain.pem").toString(),
		}),
	};
	sites["*." + domain] = sites[domain];
});

for (let s in sites) {
	console.log("http -> " + s);
	app.use(vhost(s, sites[s].app));
}

app.disable("x-powered-by");

app.use(function (req, res, next) {
	res.removeHeader("X-Powered-By");
	res.setHeader("X-Powered-By", "No one cares");
	next();
});

app.use(function (err, req, res, next) {
	if (err) {
    // Your Error Status code and message here.
    console.log(err);
		res.status(500).json({ error: "Generic server error.  Is your file too large?" });
		return;
	}
	// Continue
});

const httpServer = http.createServer(httpVer);
const httpsServer = https.createServer(
	{
		SNICallback: function (domain, cb) {
			if (domain in sites) {
				cb(null, sites[domain].context);
			} else {
				for (const [key, value] of Object.entries(sites)) {
					if (domain.indexOf(key) >= 0) {
						cb(null, value.context);
						return;
					}
				}
				cb(null, sites["primarydomain.com"].context);
			}
		},
		key: fs.readFileSync("/etc/letsencrypt/live/" + config.domain + "/privkey.pem"),
		cert: fs.readFileSync("/etc/letsencrypt/live/" + config.domain + "/fullchain.pem"),
	},
	app
);

mongoUtil.connectToServer(function (err, client) {
	if (err) {
		console.log("error connecting to db");
		console.log(err);
		exit();
	} else {
		console.log("started express");
		httpServer.listen(80, () => {
			console.log("HTTP Server running on port 80");
		});
		httpsServer.listen(443, () => {
			console.log("HTTPS Server running on port 443");
		});
	}
});

process.on("uncaughtException", (code) => {
	httpServer.close();
	httpsServer.close();
});

async function createInvites(res, req, total, userId) {
	var docs = [];
	var invites = [];
	for (var i = 0; i < total; i++) {
		var id = bs58.encode(crypto.randomBytes(12));
		var inv = "invite+" + bsInv.encode(crypto.randomBytes(4));
		docs[i] = { id: id, invite: inv, forUser: userId, created: new Date().toLocaleString() };
		if (req && req.body.notes) {
			docs[i]["notes"] = req.body.notes;
		} else {
			if (!res) {
				docs[i]["notes"] = "Free invites for " + userId;
			} else {
				docs[i]["notes"] = "Created by admin";
			}
		}
		invites[i] = inv;
	}
	mongoUtil.getInviteModel().create(docs, function (err) {
		if (err) {
			if (res) {
				res.status(500).send({ error: "Failed to update database" });
			}
			return;
		}
		if (res) {
			res.status(201).send({ success: "Created " + total + " invites", invites: invites });
		}
	});
}

function isAlphanumeric(test) {
	var testSanitized = test.replace(/[^a-zA-Z\d]/gm, "");
	return testSanitized == test;
}
