// Load required packages
var mongoose = require('mongoose');

// Define our token schema
var TokenSchema   = new mongoose.Schema({
  value: { type: String, required: true },
  userId: { type: String, required: true },
  clientId: { type: String, required: true },
  scope: { type: String, required: true },
  IntentId: { type: String, required: true },
  IssuedAt: { type: Number, required: true },
  ExpiresIn: { type: Number, required: true },
  Status: { type: String, required: true }
});

// Export the Mongoose model
module.exports = mongoose.model('Token', TokenSchema);