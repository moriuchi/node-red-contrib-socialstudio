/*
 * 
 */
module.exports = function(RED) {
    "use strict";
    var request = require("request");
    var crypto = require("crypto");
    var url = require("url");
    
    var apiEndpoint = "api.socialstudio.radian6.com"; 

    function socialstudioNode(n) {
        RED.nodes.createNode(this,n);
        this.displayName = n.displayName;

        this.request = requestAPI;
    }
    RED.nodes.registerType("socialstudio-credentials", socialstudioNode, {
        credentials: {
            userId: {type:"text"},
            displayName: {type:"text"},
            userName: {type:"text"},
            password: {type:"password"},
            clientId: {type:"text"},
            clientSecret: {type:"password"},
            accessToken: {type:"password"},
            refreshToken: {type:"password"},
            expireTime: {type:"password"}
        }
    });


    RED.httpAdmin.get('/socialstudio-credentials/auth', function(req, res) {

        if (!req.query.userName || !req.query.password || !req.query.clientId || !req.query.clientSecret ||
            !req.query.id || !req.query.callback) {
            res.send(400);
            return;
        }
        var node_id = req.query.id;
        var callback = req.query.callback;
        var credentials = {
            userName: req.query.userName,
            password: req.query.password,
            clientId: req.query.clientId,
            clientSecret: req.query.clientSecret
        };

        var csrfToken = crypto.randomBytes(18).toString('base64').replace(/\//g, '-').replace(/\+/g, '_');
        credentials.csrfToken = csrfToken;
        res.cookie('csrf', csrfToken);

        res.redirect(url.format({
            protocol: 'https',
            hostname: apiEndpoint,
            pathname: '/login/oauth/authorize',
            query: {
                response_type: "code",
                client_id: req.query.clientId,
                state: node_id + ":" + csrfToken,
                redirect_uri: callback
            }
        }));

        RED.nodes.addCredentials(node_id, credentials);

    });

    RED.httpAdmin.get('/socialstudio-credentials/auth/callback', function(req, res) {

        if (req.query.error) {
            console.log(req.query.error);
            return res.send("ERROR: not return Authorization code");
        }

        var state = req.query.state.split(':');
        var node_id = state[0];
        var credentials = RED.nodes.getCredentials(node_id);
        if (!credentials || !credentials.clientId || !credentials.clientSecret) {
            console.log("credentials not present?");
            return res.send("ERROR: no credentials - should never happen");
        }
        if (state[1] !== credentials.csrfToken) {
            return res.status(401).send("CSRF token mismatch, possible cross-site request forgery attempt.");
        }

        request.post({
            url: 'https://' + apiEndpoint + '/oauth/token',
            json: true,
            form: {
                grant_type: 'password',
                authorizationCode: req.query.code,
                client_id: credentials.clientId,
                client_secret: credentials.clientSecret,
                username: credentials.userName,
                password: credentials.password
            },
        }, function(err, result, data) {
            if (err) {
                console.log("token error:" + err);
                node.error(err.toString());
                node.status({ fill: 'red', shape: 'ring', text: 'failed' });
                return res.send("token error:" + err.toString());
            }
            if (data.error) {
                console.log("token error: " + data.error);
                return res.send("token error:" + data.error);
            }
            credentials.accessToken = data.access_token;
            credentials.refreshToken = data.refresh_token;
            credentials.expiresIn = data.expires_in;
            credentials.expireTime = data.expires_in + (new Date().getTime()/1000);
            delete credentials.csrfToken;
            RED.nodes.addCredentials(node_id, credentials);

            request.get({
                url: 'https://' + apiEndpoint + '/v3/users/me',
                json: true,
                auth: { bearer: credentials.accessToken },
            }, function(err, result, data) {
                if (err) {
                    console.log('get user error: ' + err);
                    return res.send('get user error: ' + err.toString());
                }
                if (data.error) {
                    console.log('get user error: ' + data.error);
                    return res.send('get user error: ' + data.error.message);
                }
                credentials.displayName = data.data[0].displayName;
                credentials.userId = data.data[0].id;
                RED.nodes.addCredentials(node_id, credentials);
                res.send("<html><head></head><body>Authorised - you can close this window and return to Node-RED</body></html>");
            });
        });
    });





    function requestAPI(path, callback) {

        var node = this;
        var node_id = this.id;
        var ssCredentials = RED.nodes.getCredentials(node_id);
        var credentials = { 
            userId: ssCredentials.userId,
            userName: ssCredentials.userName,
            password: ssCredentials.password,
            clientId: ssCredentials.clientId,
            clientSecret: ssCredentials.clientSecret,
            accessToken: ssCredentials.accessToken,
            refreshToken: ssCredentials.refreshToken,
            expireTime: ssCredentials.expireTime
        };
        RED.nodes.addCredentials(node_id, credentials);

        // check token
        if (!ssCredentials.expireTime ||
            ssCredentials.expireTime < (new Date().getTime()/1000)) {
                console.log('warn - token expired. refreshToken');
                request.post({
                    url: 'https://' + apiEndpoint + '/oauth/token',
                    json: true,
                    form: {
                        grant_type: 'refresh_token',
                        refresh_token: credentials.refreshToken,
                        client_id: credentials.clientId,
                        client_secret: credentials.clientSecret,
                    },
                }, function(err, result, data) {
                    if (err) {
                        console.log(err);
                        callback(err);
                        return;
                    }
                    if (data.error) {
                        console.log(data.error);
                        callback(null, data);
                        return;
                    }
                    credentials.accessToken = data.access_token;
                    if (data.refresh_token) {
                        credentials.refreshToken = data.refresh_token;
                    }
                    credentials.expiresIn = data.expires_in;
                    credentials.expireTime = data.expires_in + (new Date().getTime()/1000);
                    RED.nodes.addCredentials(node_id, credentials);

                    node.request(path, callback);
                    return;
                });
        } else {
            var options = {
                url: 'https://' + apiEndpoint + path,
                json: true,
                auth: { bearer: credentials.accessToken }
            };
            request(options, callback);
        }
    }




    RED.httpAdmin.get('/socialstudio-topic/workspaces', function(req, res) {

        var ssNode = RED.nodes.getNode(req.query.id);
        var ssCredentials = RED.nodes.getCredentials(req.query.credentials);
        var ssConfigNode = RED.nodes.getNode(req.query.credentials);
        if (!req.query.id || !req.query.credentials ||
            !ssCredentials || !ssCredentials.accessToken || !ssCredentials.refreshToken) {
            return res.send('{"error": "Missing SocialStudio credentials"}');
        }


        var node = null;
        if (ssNode && ssNode.socialstudio) {
            node = ssNode.socialstudio;
        } else if (ssConfigNode) {
            node = ssConfigNode;
        } else {
            node = { id: req.query.credentials };
            if(ssCredentials) node.credentials = ssCredentials;
            node.request = requestAPI;
        }

        // Retrieve Workspaces
        var path = "/v1/workspaces?user=" + ssCredentials.userId + "&isMember=true";
        node.request(path, function(err, result, data){
            if (err) {
                return res.send('{"error": "request error:' + err + '"}');
            }
            if (data.error) {
	            return res.send('{"error": "(' + data.error.statusCode + ') ' + data.error.message + '"}');
            }
            if (!data.status) {
	            var errRes = data.response.errors[0];
	            return res.send('{"error": "(' + errRes.code + ') ' + errRes.message + '"}');
            }

            var resData = {};
            resData["workspaces"] = data;

            // Retrieve Media Types
            node.request("/v3/mediaTypes", function(err, result, data){
                if (err) {
                    return res.send('{"error": "request error:' + err + '"}');
                }
                if (data.error) {
                    return res.send('{"error": "request error:' + data.error + '"}');
                }
                resData["mediaTypes"] = data;

                res.send(resData);
            });
        });
    });



    RED.httpAdmin.get('/socialstudio-topic/topics', function(req, res) {

        var ssNode = RED.nodes.getNode(req.query.id);
        var ssCredentials = RED.nodes.getCredentials(req.query.credentials);
        var ssConfigNode = RED.nodes.getNode(req.query.credentials);
        if (!req.query.id || !req.query.credentials ||
            !ssCredentials || !ssCredentials.accessToken || !ssCredentials.refreshToken) {
            return res.send('{"error": "Missing SocialStudio credentials"}');
        }


        var node = null;
        if (ssNode && ssNode.socialstudio) {
            node = ssNode.socialstudio;
        } else if (ssConfigNode) {
            node = ssConfigNode;
        } else {
            node = { id: req.query.credentials };
            if(ssCredentials) node.credentials = ssCredentials;
            node.request = requestAPI;
        }

        // Retrieve Topic Profiles
        var path = "/v3/topics";
        if (req.query.workspaceid 
                && typeof req.query.workspaceid !== undefined && req.query.workspaceid !== "undefined") {
            path = path + "?workspaceGroupId=" + req.query.workspaceid;
        }

        node.request(path, function(err, result, data){
            if (err) {
                return res.send('{"error": "request error:' + err + '"}');
            }
            if (data.error) {
                return res.send('{"error": "request error:' + data.error + '"}');
            }
            res.send(data);
        });
    });


    RED.httpAdmin.get('/socialstudio-topic/topicdetail', function(req, res) {

        var ssNode = RED.nodes.getNode(req.query.id);
        var ssCredentials = RED.nodes.getCredentials(req.query.credentials);
        var ssConfigNode = RED.nodes.getNode(req.query.credentials);
        if (!req.query.id || !req.query.credentials ||
            !ssCredentials || !ssCredentials.accessToken || !ssCredentials.refreshToken) {
            return res.send('{"error": "Missing SocialStudio credentials"}');
        }


        var node = null;
        if (ssNode && ssNode.socialstudio) {
            node = ssNode.socialstudio;
        } else if (ssConfigNode) {
            node = ssConfigNode;
        } else {
            node = { id: req.query.credentials };
            if(ssCredentials) node.credentials = ssCredentials;
            node.request = requestAPI;
        }

        // Retrieve Topic Profile
        var path = "/v3/topics/" + req.query.topicid;
        node.request(path, function(err, result, data){
            if (err) {
                return res.send('{"error": "request error:' + err + '"}');
            }
            if (data.error) {
                return res.send('{"error": "request error:' + data.error + '"}');
            }

            res.send(data);
        });

    });


    function socialstudioQueryNode(n) {
        RED.nodes.createNode(this,n);
        this.topicid = n.topicid;
        this.mediatype = n.mediatype;
        this.keywordgroup = n.keywordgroup;
        this.startDate = n.startDate;
        this.endDate = n.endDate;
        this.limit = n.limit;
        this.socialstudio = RED.nodes.getNode(n.socialstudio);

        var node = this;
        if (!this.socialstudio || !this.socialstudio.credentials
            || !this.socialstudio.credentials.accessToken
            || !this.socialstudio.credentials.refreshToken) {
            this.warn("Missing socialstudio credentials");
            return;
        }

        node.on("input", function(msg) {
            var topicid = node.topicid || msg.topicid;
            var mediatype = node.mediatype || msg.mediatype;
            var keywordgroup = node.keywordgroup || msg.keywordgroup;
            var startDate = node.startDate || msg.startDate;
            var endDate = node.endDate || msg.endDate;
            var limit = node.limit || msg.limit;

            if (topicid === "") {
                node.warn("No topicId specified");
                return;
            }
            msg.topicid = topicid;
            msg.mediatype = mediatype;
            msg.keywordgroup = keywordgroup;
            msg.startDate = startDate;
            msg.endDate = endDate;
            msg.limit = limit;

            node.status({fill:"blue",shape:"dot",text:"get post data"});

            // Retrieve Posts
            var path = '/v3/posts?topics=' + topicid;

            var queryParam = [];

            if(startDate){
                var startTime = new Date(startDate).getTime();
                queryParam.push("startDate=" + startTime);
            }
            if(endDate){
                var endTime = new Date(endDate).getTime();
                queryParam.push("endDate=" + endTime);
            }
            if(mediatype){
                queryParam.push("mediaTypes=" + mediatype);
            }
            if(keywordgroup){
                queryParam.push("keywordGroups=" + keywordgroup);
            }
            if(limit){
                queryParam.push("limit=" + limit);
            }
            if(queryParam.length > 0){
                path += "&" + queryParam.join("&");
            }
            node.socialstudio.request(path, function(err, result, data) {
                if (err) {
                    node.error("request error:" + err);
                }
                if (result.error) {
                    node.error("error:" + data.error);
                }
                var resDatas = data;

                msg.payload = resDatas;
                node.status({});
                node.send(msg);
            });
        });
    }
    RED.nodes.registerType("socialstudio-topic", socialstudioQueryNode);

};
