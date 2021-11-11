const mongoose = require('mongoose');
const url = "mongodb://localhost:27017/universe?retryWrites=true&writeConcern=majority";

var _client;
var _inviteModel = mongoose.model('invites', new mongoose.Schema({ id: String, invite: String, forUser: String, notes: String, created: String }));
var _imageModel = mongoose.model('images', new mongoose.Schema({ id: String, fileName: String, userid: String, uploaded: String }));
var _userModel = mongoose.model('users', new mongoose.Schema({ id: String, invite: String, referredBy: String, email: String, username: String, password: String, salt: String, verifyCode: String, verified: Boolean, created: String }));
module.exports = {
  connectToServer: function( callback ) {
    mongoose.connect( url,  { useNewUrlParser: true, useUnifiedTopology: true }, function( err, client ) {
      _client = client;
      return callback( err );
    } );
  },

  getClient: function() {
    return _client;
  },

  getImageModel: function() {
    return _imageModel;
  },

  getUserModel: function() {
    return _userModel;
  },

  getInviteModel: function() {
    return _inviteModel;
  }
};