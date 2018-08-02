/**
 * Module dependencies.
 */

var settings = require('./src/util/Settings.js'),
    tests = require('./src/util/tests.js'),
    draw = require('./src/util/draw.js'),
    projects = require('./src/util/projects.js'),
    jade     = require('jade'),
    db = require('./src/util/db.js'),
    express = require("express"),
    jose = require('node-jose'),
    paper = require('paper'),
    socket = require('socket.io'),
    async = require('async'),
    fs = require('fs'),
    cookieParser = require('cookie-parser');
    http = require('http'),
    https = require('https'),
    session = require('express-session');

var jwks = require('./jwks.json');
var app_client_id = '6gg6doqcb4v0aru9qrks24si81';
/** 
 * SSL Logic and Server bindings
 */ 
if(settings.ssl){
  console.log("SSL Enabled");
  console.log("SSL Key File" + settings.ssl.key);
  console.log("SSL Cert Auth File" + settings.ssl.cert);

  var options = {
    key: fs.readFileSync(settings.ssl.key,'utf8'),
    cert: fs.readFileSync(settings.ssl.cert,'utf8'),
      passphrase: '1234'
  };
  var app = express(options);
  var server = https.createServer(options, app).listen(settings.port);
}else{
  var app = express();
  var server = app.listen(settings.port);
}

/** 
 * Build Client Settings that we will send to the client
 */
var clientSettings = {
  "tool": settings.tool
}

// Config Express to server static files from /
app.use(express.static(__dirname + '/'));

// Sessions
app.use(cookieParser());
app.use(session({secret: 'secret', key: 'express.sid'}));


// ROUTES
// Index page
app.get('/', function (req, res, next) {
    var token = req.query.token;
    //var token = 'eyJraWQiOiJ5YVwvV0taMTZlTVwvalVjRVJpV0N6dk5DTjI3a2pQWm5lS2ttdUVXRjlcL3ZVPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJhMjcxM2MzOC01ZTRiLTQ5ZTktOWUxNS1hNGUzNDc3NDI5NzUiLCJjdXN0b206bGFzdE5hbWUiOiJkZW1vIiwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLXdlc3QtMi5hbWF6b25hd3MuY29tXC91cy13ZXN0LTJfd3VxQ3ZLeW1CIiwiY29nbml0bzp1c2VybmFtZSI6InR1dG9yLWRlbW8iLCJhdWQiOiI2Z2c2ZG9xY2I0djBhcnU5cXJrczI0c2k4MSIsImV2ZW50X2lkIjoiMTE0ZjhkOWEtNzljMy0xMWU4LWI5M2EtNzkyMDJlMmY1YWYwIiwiY3VzdG9tOmZpcnN0TmFtZSI6InR1dG9yIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE1MzAwNzM5MzUsImN1c3RvbTptYWluUm9sZSI6ImNvbnN1bHRhbnQiLCJjdXN0b206c3ViUm9sZSI6InRlYWNoZXIiLCJjdXN0b206dGVuYW50IjoidHV0b3BpeWEiLCJwaG9uZV9udW1iZXIiOiIrOTQ3MTExMzUwMTIiLCJleHAiOjE1MzAxMjE3NjEsImlhdCI6MTUzMDExODE2MSwiZW1haWwiOiJzdXB1bi4xMkBjc2UubXJ0LmFjLmxrIn0.i--6vnwMm0H693FWyQT7YjR8NtKHIpPi5yIHZqNm_CXv1xekjUMBLKcEnuWhA3DTzLT2W9kaaD2w_xyQEPen_MbUE6WXEd6wX1AeafmnylKQL9U-iuNe1ykVk_ysukca5RLTN7EIn8ZOYMh8rCX2K2qNtaAwmeu0U92UN49M_X7fF0vhkwJvrQxBs_gXymU7wCF5uUVGA5kRrbcSs1bgipSgpkKET9HPRMRwXawHEJyIbuUKSYRRuj8ZYPuZxUlbplYCxsSsWgqZgxncyJJmpSgFzC6lATegLbYRBO9Ze2ksRu6nTOSy9KhozRnxUBTUFzc6xMy_UCOpoa58ffEjcA'
    console.log('token', token);
    var sections = token.split('.');
    // get the kid from the headers prior to verification
    var header = jose.util.base64url.decode(sections[0]);
    header = JSON.parse(header);
    var kid = header.kid;
    var keys = jwks['keys'];
    // search for the kid in the downloaded public keys
    var key_index = -1;
    for (var i=0; i < keys.length; i++) {
        if (kid == keys[i].kid) {
            key_index = i;
            break;
        }
    }
    if (key_index == -1) {
        console.log('Public key not found in jwks.json');
        res.send('Public key not found in jwks.json');
    }
    // construct the public key
    jose.JWK.asKey(keys[key_index]).
    then(function(result) {
        // verify the signature
        jose.JWS.createVerify(result).
        verify(token).
        then(function(result) {
            // now we can use the claims


            var claims = JSON.parse(result.payload);

            var response = {
                "statusCode": 200,
                headers: { 'Content-Type': 'application/json' },
                "body": JSON.stringify(claims)
            };
            console.log(claims)
            // additionally we can verify the token expiration
            var current_ts = Math.floor(new Date() / 1000);
            if (current_ts > claims.exp) {
                res.send('Token is expired');
            }
            // and the Audience (use claims.client_id if verifying an access token)
            if (claims.aud != app_client_id) {
                res.send('Token was not issued for this audience');
            }
            next();
        }).
        catch(function() {
            res.send('Signature verification failed');
        });
    });

}, function(req, res){
  res.sendfile(__dirname + '/src/build/index.html');
});

// Drawings
app.get('/d/*', function(req, res){
  res.sendfile(__dirname + '/src/static/html/draw.html');
});

// Front-end tests
app.get('/tests/frontend/specs_list.js', function(req, res){
  tests.specsList(function(tests){
    res.send("var specs_list = " + JSON.stringify(tests) + ";\n");
  });
});

// Used for front-end tests
app.get('/tests/frontend', function (req, res) {
  res.redirect('/tests/frontend/');
});

// Static files IE Javascript and CSS
app.use("/static", express.static(__dirname + '/src/static'));

app.use(express.static(__dirname + '/src/build/'));


// LISTEN FOR REQUESTS
var io = socket.listen(server);
io.sockets.setMaxListeners(0);

console.log("Access Etherdraw at http://"+settings.ip+":"+settings.port);

// SOCKET IO
io.sockets.on('connection', function (socket) {
  socket.on('disconnect', function () {
    console.log("Socket disconnected");
    // TODO: We should have logic here to remove a drawing from memory as we did previously
  });

  // EVENT: User stops drawing something
  // Having room as a parameter is not good for secure rooms
  socket.on('draw:progress', function (room, uid, co_ordinates,deviseWindowSize) {
    if (!projects.projects[room] || !projects.projects[room].project) {
      loadError(socket);
      return;
    }
    io.in(room).emit('draw:progress', uid, co_ordinates,deviseWindowSize);
    draw.progressExternalPath(room, JSON.parse(co_ordinates), uid,deviseWindowSize);
  });

  // EVENT: User stops drawing something
  // Having room as a parameter is not good for secure rooms
  socket.on('draw:end', function (room, uid, co_ordinates,deviseWindowSize) {
    if (!projects.projects[room] || !projects.projects[room].project) {
      loadError(socket);
      return;
    }
    io.in(room).emit('draw:end', uid, co_ordinates,deviseWindowSize);
    draw.endExternalPath(room, JSON.parse(co_ordinates), uid,deviseWindowSize);
  });

  // User joins a room
  socket.on('subscribe', function(data) {
    subscribe(socket, data);
  });

  // User clears canvas
  socket.on('canvas:clear', function(room) {
    if (!projects.projects[room] || !projects.projects[room].project) {
      loadError(socket);
      return;
    }
    draw.clearCanvas(room);
    io.in(room).emit('canvas:clear');
  });

  // User removes an item
  socket.on('item:remove', function(room, uid, itemName) {
    draw.removeItem(room, uid, itemName);
    io.sockets.in(room).emit('item:remove', uid, itemName);
  });

  // User moves one or more items on their canvas - progress
  socket.on('item:move:progress', function(room, uid, itemNames, delta) {
    draw.moveItemsProgress(room, uid, itemNames, delta);
    if (itemNames) {
      io.sockets.in(room).emit('item:move', uid, itemNames, delta);
    }
  });

  // User moves one or more items on their canvas - end
  socket.on('item:move:end', function(room, uid, itemNames, delta) {
    draw.moveItemsEnd(room, uid, itemNames, delta);
    if (itemNames) {
      io.sockets.in(room).emit('item:move', uid, itemNames, delta);
    }
  });

  // User adds a raster image
  socket.on('image:add', function(room, uid, data, position, name) {
    draw.addImage(room, uid, data, position, name);
    io.sockets.in(room).emit('image:add', uid, data, position, name);
  });

});

// Subscribe a client to a room
function subscribe(socket, data) {
  var room = data.room;

  // Subscribe the client to the room
  socket.join(room);

  // If the close timer is set, cancel it
  // if (closeTimer[room]) {
  //  clearTimeout(closeTimer[room]);
  // }

  // Send settings
  socket.emit('settings', clientSettings);

  // Create Paperjs instance for this room if it doesn't exist
  var project = projects.projects[room];
  if (!project) {
    console.log("made room");
    projects.projects[room] = {};
    // Use the view from the default project. This project is the default
    // one created when paper is instantiated. Nothing is ever written to
    // this project as each room has its own project. We share the View
    // object but that just helps it "draw" stuff to the invisible server
    // canvas.
    projects.projects[room].project = new paper.Project();
    projects.projects[room].external_paths = {};
    db.load(room, socket);
  } else { // Project exists in memory, no need to load from database
    loadFromMemory(room, socket);
  }

  // Broadcast to room the new user count -- currently broken
  var rooms = socket.adapter.rooms[room]; 
  var roomUserCount = Object.keys(rooms).length;
  io.to(room).emit('user:connect', roomUserCount);
}

// Send current project to new client
function loadFromMemory(room, socket) {
  var project = projects.projects[room].project;
  if (!project) { // Additional backup check, just in case
    db.load(room, socket);
    return;
  }
  socket.emit('loading:start');
  var value = project.exportJSON();
  socket.emit('project:load', {project: value});
  socket.emit('loading:end');
}

function loadError(socket) {
  socket.emit('project:load:error');
}
function convertDeviseToCommonXY(x,y){

    return {
        x: Math.round(x * commonCanvasWindow.width/deviseWindowSize.width),
        y: Math.round(y * commonCanvasWindow.height/deviseWindowSize.height),
    }

}
function convertCommonToDeviseXY(x,y){

    return {
        x: Math.round(x * deviseWindowSize.width/commonCanvasWindow.width),
        y: Math.round(y * deviseWindowSize.height/commonCanvasWindow.height),
    }

}

