// Load required packages
var Token = require('../models/token');

const util = require('util')



// Create endpoint /api/beers/:beer_id for GET
exports.introspectToken = function(req, res) {
  // Use the Beer model to find a specific beer
 console.log(req.params.value );

// alternative shortcut

  Token.find({ value: req.params.value }, function(err, token) {
    if (err)
      return res.send(err);
	var date = new Date(token[0].IssuedAt);
	date.setSeconds(date.getSeconds()+token[0].ExpiresIn);
	var currentDate = new Date();
	var status = false;
	if(currentDate<date)
		status = true;
	token[0].Status = status;
    res.json(token);
  });
};
