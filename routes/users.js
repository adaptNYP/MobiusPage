const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const async = require('async');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { ensureAuthenticated } = require('../config/auth');

// User model - ./ means go out this file and go in another so ../ means go out of file and folder and go in another folder or file etc
const User = require('../models/User');

const DEFAULT_PASSWORD = "#P@ssw0rd&"

// Login Page
router.get('/login', (req, res) => res.render('login'));

// // Register Page
// router.get('/register', (req, res) => res.render('register'));

// First Time Login Page
router.get('/first_login', ensureAuthenticated, (req, res) => {
	bcrypt.compare(DEFAULT_PASSWORD, req.user.password, (err, isMatch) => {
		if(err) throw err;

		if(isMatch) {
			res.render('first_login', { LoginUser: req.user, name: req.user.name});
		} else {
			res.redirect('/exLandingPage');
		}
	});
	
});

router.post('/first_login', (req,res) => {
		const {password, password2 } = req.body;
		let errors = [];
	
		// Check required fields
		if(!password || !password2) {
			errors.push({ msg: 'Please fill in all fields' });
		}
	
		// Check passwords match
		if(password !== password2) {
				errors.push({ msg: 'Passwords do not match' });
		}
	
		// Check pass length
		if(password.length < 8) {
				errors.push({ msg: 'Password should be at least 8 characters' });
		}
	
		if(errors.length > 0) {
			res.render('register', {
					errors,
					password,
					password2
			});
		}
	});
// Admin Register Page
router.get('/register_admin', ensureAuthenticated, (req, res) => {
	if (req.user.admin == true) {
		res.render('register_admin', { LoginUser: req.user, name: req.user.name, email: req.user.email, school: req.user.school, admin: req.user.admin });
	}
	else {
		req.flash('error_msg', 'Only admins allowed. Please log in with admin account');
		res.redirect('/exLandingPage');
	}
});

router.post('/register_admin', ensureAuthenticated, async (req, res) => {
	const { name, email, school, school_admin, admin } = req.body;
	var is_admin = false;
	if (admin === "admin") {
		is_admin = true;
	}
	let errors = [];
	var school_final = req.user.school;
	var email_final = email.trim().toLowerCase();
	if (req.user.email == "mobiusnyp@gmail.com") {
		var school_final = school_admin
		if (school_admin == null) {
			errors.push({ msg: 'Please fill in the user\'s school' });
		}
	}

	// Check required fields
	if (name == null || email == null || school == null) {
		errors.push({ msg: 'Please fill in all fields' });
	}
	if (errors.length > 0) {
		res.render('register_admin', {
			LoginUser: req.user,
			errors,
			name,
			email,
			school,
			admin
		});
		return
	}

	try {
		user = await User.findOne({ email: email_final })
		if (user) {
			errors.push({ msg: 'Email is already registered' });
			res.render('register_admin', {
				LoginUser: req.user,
				errors,
				name,
				email,
				school,
				admin
			});
			return
		}
		var password_salt = await bcrypt.genSalt(10)
		var hashed_password = await bcrypt.hash(DEFAULT_PASSWORD, password_salt)
		var newUser = new User()
		newUser.name = name
		newUser.email = email_final
		newUser.password = hashed_password
		newUser.school = school_final
		newUser.admin = is_admin
		await newUser.save()
		req.flash('success_msg', 'New user registered and can log in');
		res.redirect('/users/register_admin');
	} catch (err) {
		console.log("[Error]", err)
	}
})

// // Register Handle
// router.post('/register', (req,res) => {
// 	const { name, email, password, password2 } = req.body;
// 	let errors = [];

// 	// Check required fields
// 	if(!name || !email || !password || !password2) {
// 			errors.push({ msg: 'Please fill in all fields' });
// 	}

// 	// Check passwords match
// 	if(password !== password2) {
// 			errors.push({ msg: 'Passwords do not match' });
// 	}

// 	// Check pass length
// 	if(password.length < 8) {
// 			errors.push({ msg: 'Password should be at least 8 characters' });
// 	}

// 	if(errors.length > 0) {
// 		res.render('register', {
// 				errors,
// 				name,
// 				email,
// 				password,
// 				password2
// 		});
// 	}
// 	else {
// 		// Validation passed - Mongoose works like this - We create a model (e.g. user) and there's methods that can be called in that model (save, find etc)
// 		User.findOne({ email: email })
// 		.then(user => {
// 				if(user) {
// 						// User exists
// 						errors.push({ msg: 'Email is already registered' });
// 						res.render('register', {
// 								errors,
// 								name,
// 								email,
// 								password,
// 								password2
// 						});
// 				} else {
// 						const newUser = new User({
// 								name,
// 								email,
// 								password
// 						});

// 						// Hash Password
// 						bcrypt.genSalt(10, (err, salt) => 
// 								bcrypt.hash(newUser.password, salt, (err, hash) => {
// 										if(err) throw err;
// 										// Set password to hashed
// 										newUser.password = hash;
// 										// Save user
// 										newUser.save()
// 										.then(user => {
// 												req.flash('success_msg', 'You are now registered and can log in');
// 												res.redirect('/users/login');
// 										})
// 										.catch(err => console.log(err));
// 						}))
// 				}
// 		});
// 	}
// });



// Login Handle
router.post('/login', (req, res, next) => {
	passport.authenticate('local', {
		successRedirect: '/users/first_login',
		failureRedirect: '/users/login',
		failureFlash: true
	})(req, res, next);
});

// Logout Handle
router.get('/logout', (req, res) => {
	req.logout();
	req.flash('success_msg', 'You are logged out');
	res.redirect('/users/login');
});

//Forgot password
router.get('/forgot', (req, res) => {
	res.render('forgot');
});

router.post('/forgot', function (req, res, next) {
	async.waterfall([
		function (done) {
			crypto.randomBytes(20, function (err, buf) {
				//generate random token
				var token = buf.toString('hex');
				done(err, token);
			});
		},
		function (token, done) {
			//check if email given is registered with mobius
			User.findOne({ email: req.body.email }, function (err, user) {
				if (!user) {
					req.flash('error', 'No account with that email address exists.');
					return res.redirect('/users/forgot');
				}

				//token is assigned to the user
				//valid for only an hour
				user.resetPasswordToken = token;
				user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

				user.save(function (err) {
					done(err, token, user);
				});
			});
		},
		//Send the email to user
		function (token, user, done) {
			var smtpTransport = nodemailer.createTransport({
				service: 'gmail',
				auth: {
					user: 'servertestNYP@gmail.com',
					pass: 'Servertest123!'
				}
			});
			var mailOptions = {
				to: user.email,
				from: 'servertestNYP@gmail.com',
				subject: 'Mobius Application Password Reset',
				text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
					'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
					'http://' + req.headers.host + '/users/reset/' + token + '\n\n' +
					'If you did not request this, please ignore this email and your password will remain unchanged.\n'
			};
			smtpTransport.sendMail(mailOptions, function (err) {
				console.log('Mail sent!');
				req.flash('success_msg', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
				done(err, 'done');
			});
		}
	], function (err) {
		if (err) return next(err);
		res.redirect('/users/forgot');
	});
});

//link in email is clicked and redirected to reset password page
router.get('/reset/:token', function (req, res) {
	User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function (err, user) {
		if (!user) {
			req.flash('error', 'Password reset token is invalid or has expired.');
			return res.redirect('/users/forgot');
		}
		res.render('reset', { token: req.params.token });
	});
});

//Saving new password
router.post('/reset/:token', function (req, res) {
	async.waterfall([
		function (done) {
			User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function (err, user) {
				if (!user) {
					req.flash('error', 'Password reset token is invalid or has expired.');
					return res.redirect('back');
				}

				const { password, confirm } = req.body;
				let errors = [];


				// Check required fields
				if (!confirm || !password) {
					req.flash("error", "Please fill in all fields");
					// errors.push({ msg: 'Please fill in all fields' });
					return res.redirect('back');
				}

				// Check pass length
				if (password.length < 8) {
					req.flash("error", "Password should be at least 8 characters");
					// errors.push({ msg: 'Password should be at least 8 characters' });
					return res.redirect('back');

				}


				if (req.body.password !== req.body.confirm) {
					// errors.push({ msg: 'Passwords do not match.' });
					req.flash("error", "Passwords do not match.");
					return res.redirect('back');

				}
				else {
					bcrypt.genSalt(10, (err, salt) =>
						bcrypt.hash(req.body.password, salt, (err, hash) => {
							if (err) throw err;
							// Set password to hashed
							user.password = hash;
							user.resetPasswordToken = undefined;
							user.resetPasswordExpires = undefined;
							// Save user
							user.save(function (err) {
								req.logIn(user, function (err) {
									done(err, user);
								});
							});
						}))
				}
			});
		},
		//Upon success in changing password
		//An email will be sent to use as a receipt
		function (user, done) {
			var smtpTransport = nodemailer.createTransport({
				service: 'gmail',
				auth: {
					user: 'servertestNYP@gmail.com',
					pass: 'Servertest123!'
				}
			});
			var mailOptions = {
				to: user.email,
				from: 'servertestNYP@gmail.com',
				subject: 'Mobius Application Password Reset',
				text: 'Hello,\n\n' +
					'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
			};
			smtpTransport.sendMail(mailOptions, function (err) {
				console.log('Mail sent!');
				req.flash('success_msg', 'Success! Your password has been changed.');
				done(err);
			});
		}
	], function (err) {
		res.redirect('/exLandingPage');
	});
});

module.exports = router;